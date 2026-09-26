/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.revetsec;

import com.revetsec.ContractSupport.SourceAnalysis;
import com.sun.source.tree.CaseTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.ConditionalExpressionTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.MemberReferenceTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.NewArrayTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.ParenthesizedTree;
import com.sun.source.tree.SwitchExpressionTree;
import com.sun.source.tree.SynchronizedTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.TypeCastTree;
import com.sun.source.tree.VariableTree;
import com.sun.source.tree.YieldTree;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.NestingKind;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Source-level policy guards for properties functional tests cannot see (plan 12.3 M0, R4, R10, R18, 14.6, and M1's
 * G6-4, G6-10 and G7-7; Pyranid precedent). Two mechanisms check {@code src/main/java}:
 * <ul>
 *   <li>regular expressions, each rule a list of alternatives, matched over each whole file after Unicode escapes
 *   are translated and comments and string literals removed, so only live code counts and a construct split
 *   across lines still matches;</li>
 *   <li>javac-attributed checks for what text cannot see reliably: {@code synchronized} however it is spelled,
 *   banned methods and constructors reached through calls, method references, {@code new} or {@code super(...)},
 *   however the call is qualified (see {@link #MEMBER_BANS}), classes that extend or implement a banned
 *   supertype ({@link #SUPERTYPE_BANS}), and mutable static fields ({@code mutable-static}, below).</li>
 * </ul>
 * Most rules apply to every file. {@code constant-time-comparison} applies only where sealing keys and sealed state
 * are handled ({@code internal.crypto}, {@code StateSealer.java} and {@code SealingKey.java}), {@code ascii-case-fold}
 * only to {@code scim} and {@code internal.json}, and {@code logging} everywhere except {@link #OBSERVER_DISPATCH}.
 * <p>
 * {@code mutable-static} (R4, G6-10) reports every static field that is not final, and every static final field
 * whose declared type, or the type of a value its initializer can take, is
 * <ul>
 *   <li>an array, unless that value is an empty array ({@code new T[0]} or <code>{}</code>);</li>
 *   <li>a {@code java.util.concurrent.atomic} type ({@code AtomicLong}, {@code LongAdder}, ...) or a subclass of
 *   one;</li>
 *   <li>a {@code StringBuilder} or {@code StringBuffer};</li>
 *   <li>a collection or map, unless that value comes from {@code List}, {@code Set} or {@code Map} {@code .of},
 *   {@code .ofEntries} or {@code .copyOf} (a blank final assigned in a static block is reported; the element types
 *   of such a collection are not examined).</li>
 * </ul>
 * The values an initializer can take are the initializer itself, without parentheses and casts, or each branch of a
 * conditional or switch expression, because javac types such an expression by the least upper bound of its branches,
 * which can hide a mutable type ({@code AtomicLong} and {@code AtomicInteger} meet at {@code Number}). A null literal
 * holds nothing. Interface constants are static final fields too. A reviewed exception is a row of
 * {@link #MUTABLE_STATIC_ALLOWLIST}, and a malformed, repeated or stale row is itself a violation.
 * <p>
 * Markdown documentation comments ({@code ///}, JEP 467) are banned too, because whether javac sees them depends on
 * the JDK that runs the contract tests, not on the source.
 * Every file must also sit in the directory of its declared package, so path-based exemptions cannot be gamed.
 * <p>
 * The banned hostname of the compromised public SAML test IdP (plan 14.4) is checked across every file in the
 * repository, binary files and base64 certificate blocks included, and the license header across every Java
 * source.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class SourcePolicyTests {
	/**
	 * The one class allowed to create the process-wide default JDK {@code HttpClient} (D36). It is exempt from
	 * {@code default-http-client} only; it may not create threads or executors of its own.
	 */
	static final String DEFAULT_HTTP_CLIENT_HOLDER = "com/revetsec/internal/http/DefaultHttpClientHolder.java";

	/**
	 * The one class allowed to use {@code java.util.logging} or {@code System.Logger} (G6-4, R16): it contains an
	 * observer's failure and logs it at {@code FINE} on the {@code com.revetsec} logger. It is exempt from
	 * {@code logging} only.
	 */
	static final String OBSERVER_DISPATCH = "com/revetsec/internal/ObserverDispatch.java";

	/**
	 * Reviewed exceptions to {@code mutable-static} (R4, G6-10), one row per field:
	 * <code>{"&lt;binary name of the declaring class&gt;", "&lt;field name&gt;", "&lt;why it is safe&gt;"}</code>,
	 * such as
	 * <code>{"com.revetsec.internal.Example$Table", "VALUES", "private lookup table, never written after class
	 * initialization"},</code>. The class is spelled the way violation messages print it ({@code Outer$Nested}).
	 * <p>
	 * Adding an exception is a one-line change: append a row, with its trailing comma. A row that is malformed (not
	 * exactly three values, or a blank value or one with surrounding whitespace), repeats an earlier row, or names no
	 * field this rule reports is a violation, so entries cannot go stale. Each row is a reviewed decision, and each
	 * arrives with the code that declares its field: in M1, the set-once accessor field in
	 * {@code internal.crypto.SealedStateAccess}.
	 */
	static final List<List<String>> MUTABLE_STATIC_ALLOWLIST = rows(new String[][]{
			{"com.revetsec.internal.crypto.SealedStateAccess", "operations", "set-once accessor (G6-10, the JDK "
					+ "SharedSecrets pattern): volatile, written at most once, under a lock, by StateSealer's static "
					+ "initializer; a second set throws IllegalStateException"},
	});

	private static final String INTERNAL_XML = "com/revetsec/internal/xml/";
	private static final String INTERNAL_JSON = "com/revetsec/internal/json/";
	private static final String INTERNAL_CRYPTO = "com/revetsec/internal/crypto/";
	private static final String SAML = "com/revetsec/saml/";
	private static final String SCIM = "com/revetsec/scim/";

	/**
	 * The files outside {@code internal.crypto} that hold sealing keys or open sealed state (R10).
	 */
	private static final Set<String> SEALER_FILES = Set.of("com/revetsec/StateSealer.java",
			"com/revetsec/SealingKey.java");

	private static final String MUTABLE_STATIC_ALLOWLIST_NAME = "SourcePolicyTests.MUTABLE_STATIC_ALLOWLIST";
	private static final String ATOMIC_PACKAGE = "java.util.concurrent.atomic";

	/**
	 * The immutable collection factories that may initialize a static final collection or map.
	 */
	private static final Set<String> IMMUTABLE_COLLECTION_OWNERS = Set.of("java.util.List", "java.util.Set",
			"java.util.Map");
	private static final Set<String> IMMUTABLE_COLLECTION_FACTORIES = Set.of("of", "ofEntries", "copyOf");

	/**
	 * The hostname is assembled from parts so this file never contains it.
	 */
	private static final Pattern BANNED_HOSTNAME = Pattern.compile("saml" + "test" + "\\." + "id",
			Pattern.CASE_INSENSITIVE);

	/**
	 * Base64 blocks that may hide the hostname in a text file: PEM bodies and XML signature certificates.
	 */
	private static final Pattern BASE64_BLOCK = Pattern.compile(
			"-----BEGIN [A-Z0-9 ]+-----([A-Za-z0-9+/=\\s]+)-----END "
					+ "|<(?:[\\w.-]+:)?X509Certificate>([A-Za-z0-9+/=\\s]+)<");

	private static final Pattern JAR_NOTICE = Pattern.compile("Revetsec\nCopyright 2026 Revetware LLC\\.?\n");

	static final String SYNCHRONIZED = "synchronized";
	static final String BACKGROUND_WORK = "background-work";
	static final String DEFAULT_HTTP_CLIENT = "default-http-client";
	static final String PRINT_STACK_TRACE = "print-stack-trace";
	static final String LOCALE_LESS_CASE_CONVERSION = "locale-less-case-conversion";
	static final String XML_FACTORY_OUTSIDE_INTERNAL_XML = "xml-factory-outside-internal-xml";
	static final String JVM_GLOBAL_MUTATION = "jvm-global-mutation";
	static final String MULTI_ARGUMENT_URI = "multi-argument-uri";
	static final String PACKAGE_PATH_MISMATCH = "package-path-mismatch";
	static final String MARKDOWN_DOC_COMMENT = "markdown-doc-comment";
	static final String CONSTANT_TIME_COMPARISON = "constant-time-comparison";
	static final String ASCII_CASE_FOLD = "ascii-case-fold";
	static final String LOGGING = "logging";
	static final String MUTABLE_STATIC = "mutable-static";

	/**
	 * Alternative IDs of the checks that are neither a regular expression nor a table entry.
	 */
	static final String SYNCHRONIZED_METHOD_ALTERNATIVE = SYNCHRONIZED + " method modifier";
	static final String SYNCHRONIZED_STATEMENT_ALTERNATIVE = SYNCHRONIZED + " statement";
	static final String PACKAGE_PATH_MISMATCH_ALTERNATIVE = PACKAGE_PATH_MISMATCH + " declared package";
	static final String MARKDOWN_DOC_COMMENT_ALTERNATIVE = MARKDOWN_DOC_COMMENT + " /// line comment";
	static final String MUTABLE_STATIC_NON_FINAL_ALTERNATIVE = MUTABLE_STATIC + " non-final static field";
	static final String MUTABLE_STATIC_ARRAY_ALTERNATIVE = MUTABLE_STATIC + " static final non-empty array";
	static final String MUTABLE_STATIC_ATOMIC_ALTERNATIVE = MUTABLE_STATIC + " static final " + ATOMIC_PACKAGE
			+ " type";
	static final String MUTABLE_STATIC_STRING_BUILDER_ALTERNATIVE = MUTABLE_STATIC
			+ " static final StringBuilder or StringBuffer";
	static final String MUTABLE_STATIC_COLLECTION_ALTERNATIVE = MUTABLE_STATIC + " static final collection or map "
			+ "not initialized by List, Set or Map .of, .ofEntries or .copyOf";

	/**
	 * One banned construct: an ID used in messages, the regular-expression alternatives that detect it textually
	 * (a rule detected only by javac-attributed checks has none), the source files it applies to (paths relative to
	 * the source root, with {@code /}), and why it is banned.
	 */
	static final class Rule {
		private final String id;
		private final List<String> alternatives;
		private final List<Pattern> patterns;
		private final Predicate<String> appliesTo;
		private final String reason;

		Rule(String id, List<String> alternatives, Predicate<String> appliesTo, String reason) {
			this.id = id;
			this.alternatives = List.copyOf(alternatives);
			this.patterns = alternatives.stream().map(regex -> Pattern.compile(regex, Pattern.MULTILINE)).toList();
			this.appliesTo = appliesTo;
			this.reason = reason;
		}

		String getId() {
			return this.id;
		}

		String alternativeId(int index) {
			return this.id + " /" + this.alternatives.get(index) + "/";
		}
	}

	/**
	 * A banned method or constructor, matched on javac-resolved method calls, method references, instance creations
	 * (anonymous classes included) and explicit {@code super(...)} or {@code this(...)} calls: a member whose name
	 * matches {@code names} ({@code <init>} for constructors), declared in {@code owner} or any subtype of it, with a
	 * parameter count from {@code minimumParameters} to {@code maximumParameters}.
	 */
	static final class MemberBan {
		private final String ruleId;
		private final String owner;
		private final Pattern names;
		private final int minimumParameters;
		private final int maximumParameters;

		MemberBan(String ruleId, String owner, String names) {
			this(ruleId, owner, names, 0, Integer.MAX_VALUE);
		}

		MemberBan(String ruleId, String owner, String names, int minimumParameters, int maximumParameters) {
			this.ruleId = ruleId;
			this.owner = owner;
			this.names = Pattern.compile(names);
			this.minimumParameters = minimumParameters;
			this.maximumParameters = maximumParameters;
		}

		String alternativeId() {
			return this.ruleId + " " + this.owner + "#/" + this.names.pattern() + "/ with " + this.minimumParameters
					+ (this.maximumParameters == Integer.MAX_VALUE ? " or more" : " to " + this.maximumParameters)
					+ " parameters";
		}
	}

	/**
	 * A banned supertype: no named class may extend or implement {@code owner}, directly or indirectly.
	 */
	static final class SupertypeBan {
		private final String ruleId;
		private final String owner;

		SupertypeBan(String ruleId, String owner) {
			this.ruleId = ruleId;
			this.owner = owner;
		}

		String alternativeId() {
			return this.ruleId + " class extending or implementing " + this.owner;
		}
	}

	/**
	 * One finding: the rule, the file (relative to the source root) and line, which alternative found it, and for
	 * {@code mutable-static} the field, as {@code <binary class name>#<field name>} (empty otherwise).
	 */
	static final class Detection {
		private final String ruleId;
		private final String path;
		private final int line;
		private final String alternativeId;
		private final String subject;

		Detection(String ruleId, String path, int line, String alternativeId) {
			this(ruleId, path, line, alternativeId, "");
		}

		Detection(String ruleId, String path, int line, String alternativeId, String subject) {
			this.ruleId = ruleId;
			this.path = path;
			this.line = line;
			this.alternativeId = alternativeId;
			this.subject = subject;
		}

		/**
		 * {@code <rule> <path>:<line>}, the prefix of the violation message.
		 */
		String getKey() {
			return this.ruleId + " " + this.path + ":" + this.line;
		}

		String getAlternativeId() {
			return this.alternativeId;
		}

		/**
		 * {@code <key>: [<subjects>: ]<reason>}, where {@code subjects} are the fields reported on this line.
		 */
		String getMessage(Collection<String> subjects) {
			return getKey() + ": " + (subjects.isEmpty() ? "" : String.join(", ", subjects) + ": ")
					+ rule(this.ruleId).reason;
		}
	}

	static final List<Rule> MAIN_SOURCE_RULES = List.of(
			new Rule(SYNCHRONIZED, List.of(), SourcePolicyTests::everywhere,
					"use ReentrantLock; monitors pin virtual threads on JDK 17 and 21 (R4)"),
			new Rule(BACKGROUND_WORK, List.of("\\bScheduledExecutorService\\b"), SourcePolicyTests::everywhere,
					"Revetsec code starts no threads, executors, timers or cleaners and uses no shared pool, and "
							+ "refreshes run on caller threads; the JDK HttpClient's own threads are D36's documented "
							+ "exception (R4)"),
			new Rule(DEFAULT_HTTP_CLIENT, List.of("\\bHttpClient\\s*(?:\\.|::)\\s*(?:newHttpClient|newBuilder)\\b"),
					path -> !path.equals(DEFAULT_HTTP_CLIENT_HOLDER),
					"only " + DEFAULT_HTTP_CLIENT_HOLDER + " creates the default HttpClient (D36)"),
			new Rule("insecure-random", List.of(
					"\\bjava\\s*\\.\\s*util\\s*\\.\\s*Random\\b",
					"\\bjava\\s*\\.\\s*util\\s*\\.\\s*SplittableRandom\\b",
					"\\bjava\\s*\\.\\s*util\\s*\\.\\s*concurrent\\s*\\.\\s*ThreadLocalRandom\\b",
					"\\bjava\\s*\\.\\s*util\\s*\\.\\s*random\\b",
					"(?<![\\w.$])Random\\b",
					"(?<![\\w.$])SplittableRandom\\b",
					"(?<![\\w.$])ThreadLocalRandom\\b",
					"(?<![\\w.$])RandomGenerator\\b",
					"(?<![\\w.$])RandomGeneratorFactory\\b",
					"\\bMath\\s*(?:\\.|::)\\s*random\\b",
					"\\bStrictMath\\s*(?:\\.|::)\\s*random\\b"),
					SourcePolicyTests::everywhere, "use the instance SecureRandom behind the entropy seam (R6)"),
			new Rule("console-output", List.of("\\bSystem\\s*\\.\\s*out\\b", "\\bSystem\\s*\\.\\s*err\\b"),
					SourcePolicyTests::everywhere, "Revetsec never writes to System.out or System.err (R16)"),
			new Rule(PRINT_STACK_TRACE, List.of(), SourcePolicyTests::everywhere,
					"stack traces may carry secrets and must not be printed (R9, R16)"),
			new Rule(LOCALE_LESS_CASE_CONVERSION, List.of(), SourcePolicyTests::everywhere, "pass Locale.ROOT (R18)"),
			new Rule(XML_FACTORY_OUTSIDE_INTERNAL_XML, List.of(), path -> !path.startsWith(INTERNAL_XML),
					"XML parsers and transformers are created only by the hardened factories in internal.xml"),
			new Rule("xpath-in-saml", List.of("\\bXPath\\w*", "\\bjavax\\s*\\.\\s*xml\\s*\\.\\s*xpath\\b"),
					path -> path.startsWith(SAML) || path.startsWith(INTERNAL_XML),
					"SAML processing walks the verified DOM by namespace and never uses XPath (14.6)"),
			new Rule("non-namespace-dom-lookup", List.of("\\bgetElementsByTagName\\b"),
					path -> path.startsWith(SAML) || path.startsWith(INTERNAL_XML),
					"use getElementsByTagNameNS; unqualified lookups enable wrapping attacks (14.6)"),
			new Rule("java-deserialization", List.of("\\bObjectInputStream\\b", "\\bXMLDecoder\\b"),
					SourcePolicyTests::everywhere, "Java object deserialization is never used"),
			new Rule("set-accessible",
					List.of("\\bsetAccessible\\b", "\\btrySetAccessible\\b", "\\bprivateLookupIn\\b"),
					SourcePolicyTests::everywhere, "no reflection into private members (R19)"),
			new Rule("sun-internal-api", List.of("(?<![\\w.$])sun\\s*\\.\\s*(?:misc|reflect|security|nio|net|util"
							+ "|io|invoke|awt|font|java2d|rmi|management|tools|jvmstat|text|launcher|print|swing"
							+ "|instrument)\\b"),
					SourcePolicyTests::everywhere, "sun.* is JDK-internal"),
			new Rule("mime-base64-decoder", List.of("\\bgetMimeDecoder\\b"), SourcePolicyTests::everywhere,
					"the MIME decoder silently skips illegal characters (14.6)"),
			new Rule("service-loader", List.of("\\bServiceLoader\\b"), SourcePolicyTests::everywhere,
					"no ServiceLoader (R4)"),
			// The setters are javac-resolved MEMBER_BANS, so a static setter called through an instance or an
			// expression (connection.setDefaultSSLSocketFactory, Locale.ROOT.setDefault) is caught too. The live
			// Properties object that System.getProperties() returns is the one thing text must catch.
			new Rule(JVM_GLOBAL_MUTATION, List.of("\\bSystem\\s*(?:\\.|::)\\s*getProperties\\b"),
					SourcePolicyTests::everywhere, "Revetsec never mutates JVM-global settings (R4)"),
			new Rule(MULTI_ARGUMENT_URI, List.of(), SourcePolicyTests::everywhere,
					"multi-argument URI constructors re-encode components and let parameters inject; build the string "
							+ "with the internal encoders and use a single-argument constructor (14.6)"),
			new Rule(CONSTANT_TIME_COMPARISON, List.of(), SourcePolicyTests::handlesSealingKeys,
					"compare keys, tags, kids and other sealed-state values in constant time (MessageDigest.isEqual, "
							+ "through internal.crypto.ConstantTime); String and Arrays equality return at the first "
							+ "difference (R10)"),
			new Rule(ASCII_CASE_FOLD, List.of("\\bCASE_INSENSITIVE_ORDER\\b"),
					path -> path.startsWith(SCIM) || path.startsWith(INTERNAL_JSON),
					"fold case with internal.json.AsciiCase; the JDK's case-insensitive comparisons and case mappings "
							+ "also fold non-ASCII letters, even with Locale.ROOT (dotless i uppercases to I, and the "
							+ "Kelvin sign lowercases to k), so SCIM names that differ would be treated as one (G7-7)"),
			new Rule(LOGGING, List.of(
					"\\bjava\\s*\\.\\s*util\\s*\\.\\s*logging\\b",
					"\\bSystem\\s*\\.\\s*Logger(?:Finder)?\\b"),
					path -> !path.equals(OBSERVER_DISPATCH),
					"only " + OBSERVER_DISPATCH + " logs, and only a contained observer failure; everything else "
							+ "reports through observers (G6-4, R16)"),
			new Rule(MUTABLE_STATIC, List.of(), SourcePolicyTests::everywhere,
					"no mutable static state: make the field final and immutable (List, Set or Map .of or .copyOf for "
							+ "collections), or add a reviewed row to " + MUTABLE_STATIC_ALLOWLIST_NAME + " (R4, G6-10)"),
			new Rule(PACKAGE_PATH_MISMATCH, List.of(), SourcePolicyTests::everywhere,
					"a file must sit in the directory of its declared package, or path-based exemptions do not hold"),
			new Rule(MARKDOWN_DOC_COMMENT, List.of(), SourcePolicyTests::everywhere,
					"use /** */ Javadoc; JDK 17/21 tooling ignores /// Markdown doc comments, so R20 and @since would "
							+ "pass or fail depending on the JDK (JEP 467)"));

	/**
	 * Banned methods and constructors, checked on javac-resolved references (see {@link MemberBan}).
	 */
	static final List<MemberBan> MEMBER_BANS = List.of(
			new MemberBan(BACKGROUND_WORK, "java.lang.Thread", "<init>"),
			new MemberBan(BACKGROUND_WORK, "java.lang.Thread", "start"),
			new MemberBan(BACKGROUND_WORK, "java.util.Timer", "<init>"),
			new MemberBan(BACKGROUND_WORK, "java.util.TimerTask", "<init>"),
			new MemberBan(BACKGROUND_WORK, "java.util.concurrent.Executor", "<init>"),
			new MemberBan(BACKGROUND_WORK, "java.util.concurrent.Executors", ".*"),
			new MemberBan(BACKGROUND_WORK, "java.util.concurrent.ForkJoinPool", "commonPool"),
			new MemberBan(BACKGROUND_WORK, "java.util.concurrent.ForkJoinTask", "fork|invokeAll"),
			new MemberBan(BACKGROUND_WORK, "java.util.concurrent.CompletionStage", "\\w+Async"),
			new MemberBan(BACKGROUND_WORK, "java.util.concurrent.CompletableFuture",
					"orTimeout|completeOnTimeout|delayedExecutor|defaultExecutor"),
			new MemberBan(BACKGROUND_WORK, "java.lang.ref.Cleaner", "create"),
			new MemberBan(BACKGROUND_WORK, "java.util.Collection", "parallelStream"),
			new MemberBan(BACKGROUND_WORK, "java.util.stream.BaseStream", "parallel"),
			new MemberBan(BACKGROUND_WORK, "java.util.Arrays", "parallel\\w+"),
			new MemberBan(PRINT_STACK_TRACE, "java.lang.Throwable", "printStackTrace"),
			new MemberBan(PRINT_STACK_TRACE, "java.lang.Thread", "dumpStack"),
			new MemberBan(LOCALE_LESS_CASE_CONVERSION, "java.lang.String", "toLowerCase|toUpperCase", 0, 0),
			new MemberBan(XML_FACTORY_OUTSIDE_INTERNAL_XML, "javax.xml.parsers.DocumentBuilderFactory", "new\\w*"),
			new MemberBan(XML_FACTORY_OUTSIDE_INTERNAL_XML, "javax.xml.parsers.SAXParserFactory", "new\\w*"),
			new MemberBan(XML_FACTORY_OUTSIDE_INTERNAL_XML, "javax.xml.transform.TransformerFactory", "new\\w*"),
			new MemberBan(XML_FACTORY_OUTSIDE_INTERNAL_XML, "javax.xml.validation.SchemaFactory", "new\\w*"),
			new MemberBan(XML_FACTORY_OUTSIDE_INTERNAL_XML, "javax.xml.stream.XMLInputFactory", "new\\w*"),
			new MemberBan(XML_FACTORY_OUTSIDE_INTERNAL_XML, "javax.xml.xpath.XPathFactory", "new\\w*"),
			new MemberBan(XML_FACTORY_OUTSIDE_INTERNAL_XML, "org.xml.sax.helpers.XMLReaderFactory", "create\\w*"),
			new MemberBan(MULTI_ARGUMENT_URI, "java.net.URI", "<init>", 2, Integer.MAX_VALUE),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.lang.System",
					"setProperty|clearProperty|setProperties|setSecurityManager|setOut|setErr|setIn"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.security.Security",
					"setProperty|addProvider|insertProviderAt|removeProvider"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.util.Locale", "setDefault"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.util.TimeZone", "setDefault"),
			new MemberBan(JVM_GLOBAL_MUTATION, "javax.net.ssl.SSLContext", "setDefault"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.Authenticator", "setDefault"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.CookieHandler", "setDefault"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.ProxySelector", "setDefault"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.ResponseCache", "setDefault"),
			// Covers HttpsURLConnection's setDefaultHostnameVerifier and setDefaultSSLSocketFactory (a subtype), and
			// the instance method setDefaultUseCaches(boolean), which also sets the JVM-wide default.
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.URLConnection",
					"setDefault\\w*|setContentHandlerFactory|setFileNameMap"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.HttpURLConnection", "setFollowRedirects"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.URL", "setURLStreamHandlerFactory"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.net.Socket", "setSocketImplFactory"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.lang.Thread", "setDefaultUncaughtExceptionHandler"),
			new MemberBan(JVM_GLOBAL_MUTATION, "java.security.Policy", "setPolicy"),
			new MemberBan(CONSTANT_TIME_COMPARISON, "java.util.Arrays", "equals"),
			new MemberBan(CONSTANT_TIME_COMPARISON, "java.lang.String", "equals|contentEquals"),
			new MemberBan(ASCII_CASE_FOLD, "java.lang.String", "equalsIgnoreCase|compareToIgnoreCase"),
			// regionMatches(boolean ignoreCase, int, String, int, int); the four-parameter form is case-sensitive.
			new MemberBan(ASCII_CASE_FOLD, "java.lang.String", "regionMatches", 5, 5),
			// equalsIgnoreCase's relatives: a fold through the JDK's case mappings, even with Locale.ROOT, merges names
			// that AsciiCase keeps apart (the locale-less forms are locale-less-case-conversion everywhere).
			new MemberBan(ASCII_CASE_FOLD, "java.lang.String", "toLowerCase|toUpperCase", 1, 1),
			new MemberBan(ASCII_CASE_FOLD, "java.lang.Character", "toLowerCase|toUpperCase|toTitleCase"),
			// Text finds java.util.logging and System.Logger wherever they are named. These catch what text cannot:
			// System.getLogger or LoggerFinder reached through a static import, and calls on a logger obtained
			// from elsewhere without naming its type.
			new MemberBan(LOGGING, "java.lang.System", "getLogger"),
			new MemberBan(LOGGING, "java.lang.System.Logger", ".*"),
			new MemberBan(LOGGING, "java.lang.System.LoggerFinder", ".*"),
			new MemberBan(LOGGING, "java.util.logging.Logger", ".*"));

	/**
	 * Banned supertypes for named classes (see {@link SupertypeBan}); instances of anonymous subclasses are caught by
	 * the constructor bans.
	 */
	static final List<SupertypeBan> SUPERTYPE_BANS = List.of(
			new SupertypeBan(BACKGROUND_WORK, "java.lang.Thread"),
			new SupertypeBan(BACKGROUND_WORK, "java.util.TimerTask"),
			new SupertypeBan(BACKGROUND_WORK, "java.util.concurrent.Executor"));

	private static final Map<String, Rule> RULES_BY_ID = MAIN_SOURCE_RULES.stream()
			.collect(Collectors.toMap(Rule::getId, rule -> rule, (first, second) -> first, LinkedHashMap::new));

	private static boolean everywhere(String relativePath) {
		return true;
	}

	private static boolean handlesSealingKeys(String relativePath) {
		return relativePath.startsWith(INTERNAL_CRYPTO) || SEALER_FILES.contains(relativePath);
	}

	/**
	 * The rows of an allowlist written as a {@code String[][]} literal, which, unlike an argument list, allows a
	 * trailing comma.
	 */
	private static List<List<String>> rows(String[][] rows) {
		return Arrays.stream(rows).map(row -> List.of(row)).toList();
	}

	@Test
	void mainSourcesFollowSourcePolicy() throws IOException {
		ContractSupport.assertNoViolations("Source policy violations",
				findViolations(ContractSupport.repositoryRoot().resolve("src/main/java")));
	}

	@Test
	void everyDetectionBelongsToADeclaredRule() {
		for (MemberBan ban : MEMBER_BANS)
			Assertions.assertTrue(RULES_BY_ID.containsKey(ban.ruleId), ban::alternativeId);
		for (SupertypeBan ban : SUPERTYPE_BANS)
			Assertions.assertTrue(RULES_BY_ID.containsKey(ban.ruleId), ban::alternativeId);
	}

	@Test
	void repositoryNeverReferencesTheCompromisedSamlTestIdp() throws IOException {
		ContractSupport.assertNoViolations("Banned hostname found (plan 14.4: treat that public SAML test IdP as "
				+ "compromised; use the scripted IdP instead)", findBannedHostnames(ContractSupport.repositoryRoot()));
	}

	@Test
	void javaSourcesCarryTheLicenseHeader() throws IOException {
		Path root = ContractSupport.repositoryRoot();
		List<String> violations = new ArrayList<>();
		violations.addAll(findMissingLicenseHeaders(root.resolve("src/main/java")));
		violations.addAll(findMissingLicenseHeaders(root.resolve("src/test/java")));
		ContractSupport.assertNoViolations("Java sources without the Revetware Apache-2.0 header", violations);
	}

	@Test
	void jarLegalFilesMatchTheRepository() throws IOException {
		Path root = ContractSupport.repositoryRoot();
		Path metaInf = root.resolve("src/main/resources/META-INF");

		Assertions.assertArrayEquals(Files.readAllBytes(root.resolve("LICENSE")),
				Files.readAllBytes(metaInf.resolve("LICENSE")),
				"src/main/resources/META-INF/LICENSE must be a byte-for-byte copy of LICENSE");

		String jarNotice = Files.readString(metaInf.resolve("NOTICE"), StandardCharsets.UTF_8);
		Assertions.assertTrue(JAR_NOTICE.matcher(jarNotice).matches(), () -> "src/main/resources/META-INF/NOTICE must "
				+ "be exactly two lines, \"Revetsec\" and the Revetware copyright line, but was:\n" + jarNotice);

		Path repositoryNotice = root.resolve("NOTICE");
		Assertions.assertTrue(Files.isRegularFile(repositoryNotice), "The repository has no NOTICE file");
		String notice = Files.readString(repositoryNotice, StandardCharsets.UTF_8).replace("\r\n", "\n");
		Assertions.assertTrue(notice.startsWith(jarNotice),
				"NOTICE must begin with the same two lines as src/main/resources/META-INF/NOTICE");
	}

	/**
	 * Applies every source-policy check to the Java files under {@code sourceRoot}, with
	 * {@link #MUTABLE_STATIC_ALLOWLIST}.
	 */
	static List<String> findViolations(Path sourceRoot) throws IOException {
		return findViolations(sourceRoot, MUTABLE_STATIC_ALLOWLIST);
	}

	/**
	 * {@link #findViolations(Path)} with {@code mutableStaticAllowlist} in place of {@link #MUTABLE_STATIC_ALLOWLIST},
	 * so {@link ContractMetaTests} can exercise rows against the fixtures. Each detection message is
	 * {@code <rule> <path>:<line>: <reason>}, one per rule and line, sorted by path, line and rule;
	 * {@code mutable-static} names every reported field on the line before the reason, in source order and separated
	 * by {@code ", "}. A message for each malformed, repeated or stale allowlist row follows, in row order.
	 */
	static List<String> findViolations(Path sourceRoot, List<List<String>> mutableStaticAllowlist)
			throws IOException {
		List<Detection> detections = findUnfilteredDetections(sourceRoot);
		Map<String, Detection> byKey = new LinkedHashMap<>();
		Map<String, Set<String>> subjectsByKey = new LinkedHashMap<>();
		for (Detection detection : withoutAllowlisted(detections, mutableStaticAllowlist)) {
			byKey.putIfAbsent(detection.getKey(), detection);
			if (!detection.subject.isEmpty())
				subjectsByKey.computeIfAbsent(detection.getKey(), key -> new LinkedHashSet<>()).add(detection.subject);
		}
		List<String> violations = new ArrayList<>(byKey.values().stream()
				.sorted(Comparator.comparing((Detection detection) -> detection.path)
						.thenComparingInt(detection -> detection.line)
						.thenComparing(detection -> detection.ruleId))
				.map(detection -> detection.getMessage(subjectsByKey.getOrDefault(detection.getKey(), Set.of())))
				.toList());
		violations.addAll(findMutableStaticAllowlistProblems(mutableStaticAllowlist, detections));
		return List.copyOf(violations);
	}

	/**
	 * Every allowlist row that is malformed, repeats an earlier row, or names no field that {@code mutable-static}
	 * reports in {@code detections} (a misspelled class, such as the canonical {@code Outer.Nested}, a renamed or
	 * removed field, or one that is no longer mutable).
	 */
	private static List<String> findMutableStaticAllowlistProblems(List<List<String>> allowlist,
			List<Detection> detections) {
		Set<String> reportedFields = detections.stream()
				.filter(detection -> detection.ruleId.equals(MUTABLE_STATIC))
				.map(detection -> detection.subject)
				.collect(Collectors.toUnmodifiableSet());
		List<String> problems = new ArrayList<>();
		Set<String> seen = new HashSet<>();
		for (int index = 0; index < allowlist.size(); ++index) {
			List<String> row = allowlist.get(index);
			if (!isWellFormedAllowlistRow(row)) {
				problems.add(MUTABLE_STATIC + " " + MUTABLE_STATIC_ALLOWLIST_NAME + " row " + (index + 1) + ": malformed "
						+ "row; expected {\"<binary class name>\", \"<field name>\", \"<why it is safe>\"}, with no blank "
						+ "value and no surrounding whitespace");
				continue;
			}
			String field = allowlistedField(row);
			String entry = MUTABLE_STATIC + " " + MUTABLE_STATIC_ALLOWLIST_NAME + " entry \"" + field + "\": ";
			if (!seen.add(field))
				problems.add(entry + "duplicate entry; list each field once");
			else if (!reportedFields.contains(field))
				problems.add(entry + "stale or misspelled entry; name a field that " + MUTABLE_STATIC + " reports, by "
						+ "the binary name of its class (Outer$Nested, as violation messages print it) and its name");
		}
		return List.copyOf(problems);
	}

	private static boolean isWellFormedAllowlistRow(List<String> row) {
		return row.size() == 3 && row.stream().noneMatch(value -> value.isBlank() || !value.strip().equals(value));
	}

	private static String allowlistedField(List<String> row) {
		return row.get(0) + "#" + row.get(1);
	}

	/**
	 * {@code detections} without the {@code mutable-static} ones for fields that a well-formed row of
	 * {@code allowlist} names. A malformed row exempts nothing.
	 */
	private static List<Detection> withoutAllowlisted(List<Detection> detections, List<List<String>> allowlist) {
		Set<String> allowlisted = allowlist.stream()
				.filter(SourcePolicyTests::isWellFormedAllowlistRow)
				.map(SourcePolicyTests::allowlistedField)
				.collect(Collectors.toUnmodifiableSet());
		return detections.stream()
				.filter(detection -> !(detection.ruleId.equals(MUTABLE_STATIC)
						&& allowlisted.contains(detection.subject)))
				.toList();
	}

	private static Rule rule(String ruleId) {
		@Nullable Rule rule = RULES_BY_ID.get(ruleId);
		if (rule == null)
			throw new IllegalStateException("Unknown source-policy rule " + ruleId);
		return rule;
	}

	/**
	 * Every alternative ID a detection can carry: each regular expression, each table entry, and the special checks.
	 */
	static List<String> alternativeIds() {
		List<String> alternativeIds = new ArrayList<>();
		for (Rule rule : MAIN_SOURCE_RULES)
			for (int index = 0; index < rule.alternatives.size(); ++index)
				alternativeIds.add(rule.alternativeId(index));
		MEMBER_BANS.forEach(ban -> alternativeIds.add(ban.alternativeId()));
		SUPERTYPE_BANS.forEach(ban -> alternativeIds.add(ban.alternativeId()));
		alternativeIds.addAll(List.of(SYNCHRONIZED_METHOD_ALTERNATIVE, SYNCHRONIZED_STATEMENT_ALTERNATIVE,
				PACKAGE_PATH_MISMATCH_ALTERNATIVE, MARKDOWN_DOC_COMMENT_ALTERNATIVE,
				MUTABLE_STATIC_NON_FINAL_ALTERNATIVE, MUTABLE_STATIC_ARRAY_ALTERNATIVE, MUTABLE_STATIC_ATOMIC_ALTERNATIVE,
				MUTABLE_STATIC_STRING_BUILDER_ALTERNATIVE, MUTABLE_STATIC_COLLECTION_ALTERNATIVE));
		return List.copyOf(alternativeIds);
	}

	/**
	 * Every raw finding under {@code sourceRoot}, with the alternative that produced it, except {@code mutable-static}
	 * findings for fields that {@code mutableStaticAllowlist} exempts. A line can be found by more than one
	 * alternative; {@link #findViolations(Path, List)} reports it once.
	 */
	static List<Detection> findDetections(Path sourceRoot, List<List<String>> mutableStaticAllowlist)
			throws IOException {
		return withoutAllowlisted(findUnfilteredDetections(sourceRoot), mutableStaticAllowlist);
	}

	private static List<Detection> findUnfilteredDetections(Path sourceRoot) throws IOException {
		List<Path> sources = ContractSupport.javaSources(sourceRoot);
		if (sources.isEmpty())
			return List.of();

		List<Detection> detections = new ArrayList<>();
		for (Path file : sources) {
			String relativePath = ContractSupport.relativePath(sourceRoot, file);
			ContractSupport.TranslatedSource translated = ContractSupport.translateUnicodeEscapes(
					Files.readString(file, StandardCharsets.UTF_8));
			List<Integer> lineCommentStarts = new ArrayList<>();
			String code = ContractSupport.stripCommentsAndStrings(translated, lineCommentStarts::add);

			// javac 23 and later read every line comment that starts with /// as a Markdown doc comment, whatever
			// precedes it on the line and however many slashes follow; javac 17 and 21 ignore it.
			String text = translated.getText();
			if (rule(MARKDOWN_DOC_COMMENT).appliesTo.test(relativePath))
				for (int start : lineCommentStarts)
					if (text.startsWith("///", start))
						detections.add(new Detection(MARKDOWN_DOC_COMMENT, relativePath,
								ContractSupport.lineNumber(text, start), MARKDOWN_DOC_COMMENT_ALTERNATIVE));

			for (Rule rule : MAIN_SOURCE_RULES) {
				if (!rule.appliesTo.test(relativePath))
					continue;
				for (int index = 0; index < rule.patterns.size(); ++index) {
					Matcher matcher = rule.patterns.get(index).matcher(code);
					while (matcher.find())
						detections.add(new Detection(rule.id, relativePath,
								ContractSupport.lineNumber(code, matcher.start()), rule.alternativeId(index)));
				}
			}
		}

		detections.addAll(ContractSupport.analyze(sourceRoot, SourcePolicyTests::findAttributedDetections));
		return List.copyOf(detections);
	}

	/**
	 * The javac-attributed checks: {@code synchronized}, {@link #MEMBER_BANS}, {@link #SUPERTYPE_BANS},
	 * {@code mutable-static} and the package location of each file.
	 */
	private static List<Detection> findAttributedDetections(SourceAnalysis analysis) {
		List<Detection> detections = new ArrayList<>();
		Map<MemberBan, TypeElement> memberBanOwners = new LinkedHashMap<>();
		for (MemberBan ban : MEMBER_BANS)
			memberBanOwners.put(ban, ownerType(analysis, ban.owner));
		Map<SupertypeBan, TypeElement> supertypeBanOwners = new LinkedHashMap<>();
		for (SupertypeBan ban : SUPERTYPE_BANS)
			supertypeBanOwners.put(ban, ownerType(analysis, ban.owner));
		MutableStaticCheck mutableStaticCheck = new MutableStaticCheck(analysis);
		SourcePositions positions = analysis.getTrees().getSourcePositions();

		for (CompilationUnitTree compilationUnit : analysis.getCompilationUnits()) {
			String relativePath = analysis.relativePath(compilationUnit);

			String packagePath = ContractSupport.packageName(compilationUnit).replace('.', '/');
			int lastSlash = relativePath.lastIndexOf('/');
			String directory = lastSlash < 0 ? "" : relativePath.substring(0, lastSlash);
			if (!directory.equals(packagePath)) {
				@Nullable Tree packageTree = compilationUnit.getPackage();
				int line = packageTree == null ? 1 : analysis.lineNumber(compilationUnit,
						positions.getStartPosition(compilationUnit, packageTree));
				detections.add(new Detection(PACKAGE_PATH_MISMATCH, relativePath, line,
						PACKAGE_PATH_MISMATCH_ALTERNATIVE));
			}

			new TreePathScanner<Void, Void>() {
				@Override
				public @Nullable Void visitClass(ClassTree node, Void unused) {
					@Nullable Element element = analysis.getTrees().getElement(getCurrentPath());
					if (element instanceof TypeElement type && type.getNestingKind() != NestingKind.ANONYMOUS)
						for (Map.Entry<SupertypeBan, TypeElement> ban : supertypeBanOwners.entrySet())
							if (analysis.isSubtype(type, ban.getValue()))
								detect(ban.getKey().ruleId, node, ban.getKey().alternativeId());
					return super.visitClass(node, null);
				}

				@Override
				public @Nullable Void visitMethod(MethodTree node, Void unused) {
					if (node.getModifiers().getFlags().contains(Modifier.SYNCHRONIZED))
						detect(SYNCHRONIZED, node, SYNCHRONIZED_METHOD_ALTERNATIVE);
					return super.visitMethod(node, null);
				}

				@Override
				public @Nullable Void visitSynchronized(SynchronizedTree node, Void unused) {
					detect(SYNCHRONIZED, node, SYNCHRONIZED_STATEMENT_ALTERNATIVE);
					return super.visitSynchronized(node, null);
				}

				@Override
				public @Nullable Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
					// javac's generated default constructors call super() without source; the class check covers them.
					if (isWritten(node)) {
						ExpressionTree methodSelect = node.getMethodSelect();
						long position = positions.getStartPosition(compilationUnit, methodSelect);
						if (methodSelect instanceof MemberSelectTree memberSelect)
							position = Math.max(position, positions.getEndPosition(compilationUnit, memberSelect)
									- memberSelect.getIdentifier().length());
						checkMember(analysis.getTrees().getElement(new TreePath(getCurrentPath(), methodSelect)),
								position);
					}
					return super.visitMethodInvocation(node, null);
				}

				@Override
				public @Nullable Void visitNewClass(NewClassTree node, Void unused) {
					if (isWritten(node))
						checkMember(analysis.getTrees().getElement(getCurrentPath()),
								positions.getStartPosition(compilationUnit, node));
					return super.visitNewClass(node, null);
				}

				@Override
				public @Nullable Void visitMemberReference(MemberReferenceTree node, Void unused) {
					if (isWritten(node))
						checkMember(analysis.getTrees().getElement(getCurrentPath()),
								positions.getStartPosition(compilationUnit, node));
					return super.visitMemberReference(node, null);
				}

				@Override
				public @Nullable Void visitVariable(VariableTree node, Void unused) {
					// Interface constants are implicitly static and final: the element's modifiers include both, and
					// the tree's do not.
					if (analysis.getTrees().getElement(getCurrentPath()) instanceof VariableElement field
							&& field.getKind() == ElementKind.FIELD && field.getModifiers().contains(Modifier.STATIC)
							&& field.getEnclosingElement() instanceof TypeElement declaringType) {
						String subject = analysis.getElements().getBinaryName(declaringType) + "#"
								+ field.getSimpleName();
						// The end of the type is on the line of the field's name, past any annotation lines.
						long position = positions.getEndPosition(compilationUnit, node.getType());
						if (position < 0)
							position = positions.getStartPosition(compilationUnit, node);
						for (String alternativeId : mutableStaticCheck.alternativeIds(field, getCurrentPath()))
							detect(MUTABLE_STATIC, position, alternativeId, subject);
					}
					return super.visitVariable(node, null);
				}

				private boolean isWritten(Tree node) {
					return positions.getEndPosition(compilationUnit, node) >= 0;
				}

				private void checkMember(@Nullable Element element, long position) {
					if (!(element instanceof ExecutableElement executable)
							|| !(executable.getEnclosingElement() instanceof TypeElement declaringType))
						return;
					String name = executable.getSimpleName().toString();
					int parameters = executable.getParameters().size();
					for (Map.Entry<MemberBan, TypeElement> entry : memberBanOwners.entrySet()) {
						MemberBan ban = entry.getKey();
						if (ban.names.matcher(name).matches() && parameters >= ban.minimumParameters
								&& parameters <= ban.maximumParameters
								&& analysis.isSubtype(declaringType, entry.getValue()))
							detect(ban.ruleId, position, ban.alternativeId());
					}
				}

				private void detect(String ruleId, Tree node, String alternativeId) {
					detect(ruleId, positions.getStartPosition(compilationUnit, node), alternativeId);
				}

				private void detect(String ruleId, long position, String alternativeId) {
					detect(ruleId, position, alternativeId, "");
				}

				private void detect(String ruleId, long position, String alternativeId, String subject) {
					@Nullable Rule rule = RULES_BY_ID.get(ruleId);
					if (rule != null && rule.appliesTo.test(relativePath))
						detections.add(new Detection(ruleId, relativePath,
								analysis.lineNumber(compilationUnit, position), alternativeId, subject));
				}
			}.scan(compilationUnit, null);
		}

		return detections;
	}

	/**
	 * Classifies static fields for {@code mutable-static} (see the class documentation).
	 */
	private static final class MutableStaticCheck {
		private final SourceAnalysis analysis;
		private final List<TypeElement> stringBuilders;
		private final List<TypeElement> collections;

		private MutableStaticCheck(SourceAnalysis analysis) {
			this.analysis = analysis;
			this.stringBuilders = List.of(ownerType(analysis, "java.lang.StringBuilder"),
					ownerType(analysis, "java.lang.StringBuffer"));
			this.collections = List.of(ownerType(analysis, "java.util.Collection"),
					ownerType(analysis, "java.util.Map"));
		}

		/**
		 * The alternatives that the static field at {@code fieldPath} matches: a non-final field matches the first
		 * alone; a final one matches each mutable kind of its declared type or of a value its initializer can take
		 * (see {@link #values(TreePath)}). A declared array, collection or map type is exempt only when the field has
		 * an initializer and each value it can take is exempt: the null literal, or an empty array or an immutable
		 * collection factory call respectively.
		 */
		Set<String> alternativeIds(VariableElement field, TreePath fieldPath) {
			if (!field.getModifiers().contains(Modifier.FINAL))
				return Set.of(MUTABLE_STATIC_NON_FINAL_ALTERNATIVE);

			List<TreePath> values = fieldPath.getLeaf() instanceof VariableTree variable
					&& variable.getInitializer() != null
					? values(new TreePath(fieldPath, variable.getInitializer()))
					: List.of();
			Set<String> alternativeIds = new LinkedHashSet<>();
			addMutableKinds(field.asType(), values, alternativeIds);
			for (TreePath value : values) {
				@Nullable TypeMirror type = this.analysis.getTrees().getTypeMirror(value);
				if (type != null)
					addMutableKinds(type, List.of(value), alternativeIds);
			}
			return alternativeIds;
		}

		/**
		 * Adds the alternative of each mutable kind that {@code type} is to {@code alternativeIds}. An array,
		 * collection or map type is exempt when {@code values} (the values that have this type) are not empty and each
		 * one is exempt.
		 */
		private void addMutableKinds(TypeMirror type, List<TreePath> values, Set<String> alternativeIds) {
			if (type.getKind() == TypeKind.ARRAY && !allExempt(values, MutableStaticCheck::isEmptyArray))
				alternativeIds.add(MUTABLE_STATIC_ARRAY_ALTERNATIVE);
			// The null type (a null literal) is a subtype of every reference type, and a primitive holds no shared
			// state.
			if (type.getKind() != TypeKind.DECLARED)
				return;
			if (isAtomic(type))
				alternativeIds.add(MUTABLE_STATIC_ATOMIC_ALTERNATIVE);
			if (isSubtypeOfAny(type, this.stringBuilders))
				alternativeIds.add(MUTABLE_STATIC_STRING_BUILDER_ALTERNATIVE);
			if (isSubtypeOfAny(type, this.collections) && !allExempt(values, this::isImmutableCollectionFactoryCall))
				alternativeIds.add(MUTABLE_STATIC_COLLECTION_ALTERNATIVE);
		}

		/**
		 * Returns whether there is at least one value and each one is the null literal or passes {@code exempt}.
		 */
		private static boolean allExempt(List<TreePath> values, Predicate<TreePath> exempt) {
			return !values.isEmpty() && values.stream().allMatch(value ->
					value.getLeaf().getKind() == Tree.Kind.NULL_LITERAL || exempt.test(value));
		}

		/**
		 * The values the expression at {@code initializer} can take: the expression itself without parentheses and
		 * casts, or, for a conditional or switch expression, the values of each of its branches, recursively.
		 */
		private static List<TreePath> values(TreePath initializer) {
			List<TreePath> values = new ArrayList<>();
			Deque<TreePath> pending = new ArrayDeque<>(List.of(initializer));
			while (!pending.isEmpty()) {
				TreePath value = withoutParenthesesOrCasts(pending.removeFirst());
				if (value.getLeaf() instanceof ConditionalExpressionTree conditional) {
					pending.add(new TreePath(value, conditional.getTrueExpression()));
					pending.add(new TreePath(value, conditional.getFalseExpression()));
				} else if (value.getLeaf() instanceof SwitchExpressionTree) {
					pending.addAll(switchResults(value));
				} else {
					values.add(value);
				}
			}
			return List.copyOf(values);
		}

		/**
		 * The result expressions of the switch expression at {@code switchExpression}: the body of each
		 * {@code case ... ->} rule that is an expression, and the value of each {@code yield} that belongs to this
		 * switch rather than to a switch expression nested in it.
		 */
		private static List<TreePath> switchResults(TreePath switchExpression) {
			List<TreePath> results = new ArrayList<>();
			new TreePathScanner<Void, Void>() {
				// Identity on purpose: descend into this switch expression only, never into one nested in it.
				@Override
				@SuppressWarnings("ReferenceEquality")
				public @Nullable Void visitSwitchExpression(SwitchExpressionTree node, Void unused) {
					return node == switchExpression.getLeaf() ? super.visitSwitchExpression(node, null) : null;
				}

				@Override
				public @Nullable Void visitCase(CaseTree node, Void unused) {
					if (node.getCaseKind() == CaseTree.CaseKind.RULE && node.getBody() instanceof ExpressionTree body) {
						results.add(new TreePath(getCurrentPath(), body));
						return null;
					}
					return super.visitCase(node, null);
				}

				@Override
				public @Nullable Void visitYield(YieldTree node, Void unused) {
					results.add(new TreePath(getCurrentPath(), node.getValue()));
					return null;
				}
			}.scan(switchExpression, null);
			return List.copyOf(results);
		}

		private static TreePath withoutParenthesesOrCasts(TreePath expression) {
			TreePath current = expression;
			while (true) {
				Tree leaf = current.getLeaf();
				if (leaf instanceof ParenthesizedTree parenthesized)
					current = new TreePath(current, parenthesized.getExpression());
				else if (leaf instanceof TypeCastTree cast)
					current = new TreePath(current, cast.getExpression());
				else
					return current;
			}
		}

		/**
		 * Returns whether {@code value} creates an array with no elements: {@code new T[0]...},
		 * {@code new T[]}<code>{}</code> or <code>{}</code>.
		 */
		private static boolean isEmptyArray(TreePath value) {
			if (!(value.getLeaf() instanceof NewArrayTree newArray))
				return false;
			List<? extends ExpressionTree> dimensions = newArray.getDimensions();
			if (!dimensions.isEmpty())
				return dimensions.get(0) instanceof LiteralTree literal && literal.getValue() instanceof Integer length
						&& length == 0;
			@Nullable List<? extends ExpressionTree> elements = newArray.getInitializers();
			return elements != null && elements.isEmpty();
		}

		/**
		 * Returns whether {@code type} is declared in {@code java.util.concurrent.atomic}, or extends or implements a
		 * type that is.
		 */
		private boolean isAtomic(TypeMirror type) {
			Deque<TypeMirror> pending = new ArrayDeque<>(List.of(type));
			while (!pending.isEmpty()) {
				TypeMirror current = pending.removeFirst();
				if (current instanceof DeclaredType declaredType
						&& declaredType.asElement() instanceof TypeElement element
						&& this.analysis.getElements().getPackageOf(element).getQualifiedName()
						.contentEquals(ATOMIC_PACKAGE))
					return true;
				pending.addAll(this.analysis.getTypes().directSupertypes(current));
			}
			return false;
		}

		private boolean isSubtypeOfAny(TypeMirror type, List<TypeElement> supertypes) {
			return supertypes.stream().anyMatch(supertype -> this.analysis.getTypes().isSubtype(
					this.analysis.getTypes().erasure(type), this.analysis.getTypes().erasure(supertype.asType())));
		}

		/**
		 * Returns whether {@code value} calls {@code List}, {@code Set} or {@code Map} {@code .of},
		 * {@code .ofEntries} or {@code .copyOf}, resolved by javac, so a look-alike class does not qualify.
		 */
		private boolean isImmutableCollectionFactoryCall(TreePath value) {
			if (!(value.getLeaf() instanceof MethodInvocationTree invocation))
				return false;
			@Nullable Element method = this.analysis.getTrees().getElement(
					new TreePath(value, invocation.getMethodSelect()));
			return method instanceof ExecutableElement executable && executable.getModifiers().contains(Modifier.STATIC)
					&& IMMUTABLE_COLLECTION_FACTORIES.contains(executable.getSimpleName().toString())
					&& executable.getEnclosingElement() instanceof TypeElement owner
					&& IMMUTABLE_COLLECTION_OWNERS.contains(owner.getQualifiedName().toString());
		}
	}

	private static TypeElement ownerType(SourceAnalysis analysis, String qualifiedName) {
		@Nullable TypeElement owner = analysis.getElements().getTypeElement(qualifiedName);
		if (owner == null)
			throw new IllegalStateException("A source-policy ban names " + qualifiedName
					+ ", which javac cannot resolve");
		return owner;
	}

	/**
	 * Scans every file in the repository (see {@link ContractSupport#repositoryFiles(Path)}) for the hostname of the
	 * compromised public SAML test IdP. Text files are searched directly and inside their PEM and XML-signature
	 * base64 blocks, and report {@code path:line}. Binary files (any NUL byte) are searched as Latin-1 bytes, which
	 * finds ASCII inside DER or other binary data, and again with NUL bytes removed, which finds ASCII text encoded
	 * as UTF-16; they report the path alone.
	 */
	static List<String> findBannedHostnames(Path repositoryRoot) throws IOException {
		List<String> violations = new ArrayList<>();
		for (Path file : ContractSupport.repositoryFiles(repositoryRoot)) {
			String relativePath = ContractSupport.relativePath(repositoryRoot, file);
			byte[] bytes = Files.readAllBytes(file);
			String content = new String(bytes, StandardCharsets.ISO_8859_1);

			if (!ContractSupport.isProbablyText(bytes)) {
				if (BANNED_HOSTNAME.matcher(content).find() || BANNED_HOSTNAME.matcher(withoutNulBytes(bytes)).find())
					violations.add(relativePath + " (binary)");
				continue;
			}

			Matcher matcher = BANNED_HOSTNAME.matcher(content);
			while (matcher.find())
				violations.add(relativePath + ":" + ContractSupport.lineNumber(content, matcher.start()));

			Matcher blocks = BASE64_BLOCK.matcher(content);
			while (blocks.find()) {
				String body = blocks.group(1) != null ? blocks.group(1) : blocks.group(2);
				if (body != null && containsBannedHostname(decodeBase64(body)))
					violations.add(relativePath + ":" + ContractSupport.lineNumber(content, blocks.start())
							+ " (base64 block)");
			}
		}
		return List.copyOf(violations);
	}

	private static String withoutNulBytes(byte[] bytes) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream(bytes.length);
		for (byte value : bytes)
			if (value != 0)
				outputStream.write(value);
		return new String(outputStream.toByteArray(), StandardCharsets.ISO_8859_1);
	}

	private static byte[] decodeBase64(String body) {
		try {
			return Base64.getDecoder().decode(body.replaceAll("\\s+", ""));
		} catch (IllegalArgumentException e) {
			return new byte[0];
		}
	}

	private static boolean containsBannedHostname(byte[] bytes) {
		return BANNED_HOSTNAME.matcher(new String(bytes, StandardCharsets.ISO_8859_1)).find()
				|| BANNED_HOSTNAME.matcher(withoutNulBytes(bytes)).find();
	}

	/**
	 * Returns the Java files under {@code sourceRoot} that do not begin with {@link ContractSupport#LICENSE_HEADER}.
	 */
	static List<String> findMissingLicenseHeaders(Path sourceRoot) throws IOException {
		List<String> violations = new ArrayList<>();
		for (Path file : ContractSupport.javaSources(sourceRoot)) {
			String content = Files.readString(file, StandardCharsets.UTF_8).replace("\r\n", "\n");
			if (!content.startsWith(ContractSupport.LICENSE_HEADER))
				violations.add(ContractSupport.relativePath(sourceRoot, file));
		}
		return List.copyOf(violations);
	}

	/**
	 * Visible for {@link ContractMetaTests}: the alternative IDs grouped by violation key.
	 */
	static Map<String, List<String>> alternativeIdsByKey(List<Detection> detections) {
		return detections.stream().collect(Collectors.groupingBy(Detection::getKey, LinkedHashMap::new,
				Collectors.mapping(Detection::getAlternativeId,
						Collectors.collectingAndThen(Collectors.toList(), ids -> ids.stream().distinct().sorted()
								.toList()))));
	}

	/**
	 * Visible for {@link ContractMetaTests}: rule IDs in declaration order.
	 */
	static List<String> ruleIds() {
		return MAIN_SOURCE_RULES.stream().map(Rule::getId).toList();
	}
}
