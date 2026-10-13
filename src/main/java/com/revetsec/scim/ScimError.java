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

package com.revetsec.scim;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.util.Optional;

/**
 * A fixed SCIM error with redacted detail. No request input or exception cause is retained. An
 * engine-produced filter or path syntax error may carry a UTF-16 expression offset; that offset is
 * programmatic metadata and must not be appended to the wire detail.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimError {
    private static final @NonNull ScimError INVALID_FILTER = new ScimError(400, ScimErrorType.INVALID_FILTER, "Invalid filter expression.", null);
    private static final @NonNull ScimError TOO_MANY = new ScimError(400, ScimErrorType.TOO_MANY, "Too many matching resources.", null);
    private static final @NonNull ScimError INVALID_SYNTAX = new ScimError(400, ScimErrorType.INVALID_SYNTAX, "Invalid request syntax.", null);
    private static final @NonNull ScimError INVALID_PATH = new ScimError(400, ScimErrorType.INVALID_PATH, "Invalid attribute path.", null);
    private static final @NonNull ScimError NO_TARGET = new ScimError(400, ScimErrorType.NO_TARGET, "The operation has no target.", null);
    private static final @NonNull ScimError INVALID_VALUE = new ScimError(400, ScimErrorType.INVALID_VALUE, "Invalid attribute value.", null);
    private static final @NonNull ScimError MUTABILITY = new ScimError(400, ScimErrorType.MUTABILITY, "The operation violates attribute mutability.", null);
    private static final @NonNull ScimError INVALID_VERSION = new ScimError(400, ScimErrorType.INVALID_VERSION, "Invalid SCIM version.", null);
    private static final @NonNull ScimError INVALID_CURSOR = new ScimError(400, ScimErrorType.INVALID_CURSOR, "Invalid pagination cursor.", null);
    private static final @NonNull ScimError EXPIRED_CURSOR = new ScimError(400, ScimErrorType.EXPIRED_CURSOR, "The pagination cursor has expired.", null);
    private static final @NonNull ScimError INVALID_COUNT = new ScimError(400, ScimErrorType.INVALID_COUNT, "Invalid pagination count.", null);
    private static final @NonNull ScimError UNIQUENESS = new ScimError(409, ScimErrorType.UNIQUENESS, "The operation violates attribute uniqueness.", null);
    private static final @NonNull ScimError SENSITIVE = new ScimError(403, ScimErrorType.SENSITIVE, "The sensitive operation is forbidden.", null);
    private static final @NonNull ScimError UNAUTHENTICATED = new ScimError(401, null, "Authentication is required.", null);
    private static final @NonNull ScimError FORBIDDEN = new ScimError(403, null, "The operation is forbidden.", null);
    private static final @NonNull ScimError NOT_FOUND = new ScimError(404, null, "The resource was not found.", null);
    private static final @NonNull ScimError PRECONDITION_FAILED = new ScimError(412, null, "The request precondition was not satisfied.", null);
    private static final @NonNull ScimError REQUEST_TOO_LARGE = new ScimError(413, null, "The request exceeds the size limit.", null);
    private static final @NonNull ScimError UNSUPPORTED_MEDIA_TYPE = new ScimError(415, null, "Unsupported media type.", null);
    private static final @NonNull ScimError METHOD_NOT_ALLOWED = new ScimError(405, null, "The request method is not allowed.", null);
    private static final @NonNull ScimError NOT_IMPLEMENTED = new ScimError(501, null, "The operation is not implemented.", null);
    private static final @NonNull ScimError INTERNAL_ERROR = new ScimError(500, null, "The request could not be processed.", null);
    private static final @NonNull ScimError RESPONSE_TOO_LARGE = new ScimError(500, null, "The response exceeds the size limit.", null);
    private static final @NonNull ScimError UNAVAILABLE = new ScimError(503, null, "The service is unavailable.", null);

    private final int statusCode;
    private final @Nullable ScimErrorType errorType;
    private final @NonNull String detail;
    private final @Nullable Integer expressionOffset;

    private ScimError(int statusCode, @Nullable ScimErrorType errorType, @NonNull String detail,
            @Nullable Integer expressionOffset) {
        this.statusCode = statusCode;
        this.errorType = errorType;
        this.detail = detail;
        this.expressionOffset = expressionOffset;
    }

    /**
     * Returns the HTTP status code.
     *
     * @return the HTTP status code
     * @since 1.0.0
     */
    public @NonNull Integer getStatusCode() { return statusCode; }
    /**
     * Returns the fixed SCIM error type, when defined.
     *
     * @return the fixed SCIM error type, when defined
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull ScimErrorType> getErrorType() { return Optional.ofNullable(errorType); }
    /**
     * Returns the fixed redacted detail.
     *
     * @return the fixed redacted detail
     * @since 1.0.0
     */
    public @NonNull String getDetail() { return detail; }
    /**
     * Returns the zero-based UTF-16 syntax-error offset, if the engine produced one. End-of-input
     * errors can point one unit past the final character.
     * @return the optional expression offset
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull Integer> getExpressionOffset() { return Optional.ofNullable(expressionOffset); }

    /**
     * Returns the fixed invalidFilter error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError invalidFilterInstance() { return INVALID_FILTER; }

    /**
     * Returns the fixed tooMany error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError tooManyInstance() { return TOO_MANY; }

    /**
     * Returns the fixed invalidSyntax error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError invalidSyntaxInstance() { return INVALID_SYNTAX; }

    /**
     * Returns the fixed invalidPath error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError invalidPathInstance() { return INVALID_PATH; }

    /**
     * Returns the fixed noTarget error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError noTargetInstance() { return NO_TARGET; }

    /**
     * Returns the fixed invalidValue error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError invalidValueInstance() { return INVALID_VALUE; }

    /**
     * Returns the fixed mutability error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError mutabilityInstance() { return MUTABILITY; }

    /**
     * Returns the fixed invalidVersion error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError invalidVersionInstance() { return INVALID_VERSION; }

    /**
     * Returns the fixed invalidCursor error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError invalidCursorInstance() { return INVALID_CURSOR; }

    /**
     * Returns the fixed expiredCursor error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError expiredCursorInstance() { return EXPIRED_CURSOR; }

    /**
     * Returns the fixed invalidCount error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError invalidCountInstance() { return INVALID_COUNT; }

    /**
     * Returns the fixed uniqueness error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError uniquenessInstance() { return UNIQUENESS; }

    /**
     * Returns the fixed sensitive error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError sensitiveInstance() { return SENSITIVE; }

    /**
     * Returns the fixed unauthenticated error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError unauthenticatedInstance() { return UNAUTHENTICATED; }

    /**
     * Returns the fixed forbidden error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError forbiddenInstance() { return FORBIDDEN; }

    /**
     * Returns the fixed notFound error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError notFoundInstance() { return NOT_FOUND; }

    /**
     * Returns the fixed preconditionFailed error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError preconditionFailedInstance() { return PRECONDITION_FAILED; }

    /**
     * Returns the fixed requestTooLarge error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError requestTooLargeInstance() { return REQUEST_TOO_LARGE; }

    /**
     * Returns the fixed unsupportedMediaType error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError unsupportedMediaTypeInstance() { return UNSUPPORTED_MEDIA_TYPE; }

    /**
     * Returns the fixed methodNotAllowed error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError methodNotAllowedInstance() { return METHOD_NOT_ALLOWED; }

    /**
     * Returns the fixed notImplemented error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError notImplementedInstance() { return NOT_IMPLEMENTED; }

    /**
     * Returns the fixed internalError error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError internalErrorInstance() { return INTERNAL_ERROR; }

    /**
     * Returns the fixed responseTooLarge error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError responseTooLargeInstance() { return RESPONSE_TOO_LARGE; }

    /**
     * Returns the fixed unavailable error with no expression offset.
     * @return the singleton error
     * @since 1.0.0
     */
    public static @NonNull ScimError unavailableInstance() { return UNAVAILABLE; }

    static @NonNull ScimError invalidFilterAt(int offset) {
        return withOffset(INVALID_FILTER, offset);
    }

    static @NonNull ScimError invalidPathAt(int offset) {
        return withOffset(INVALID_PATH, offset);
    }

    private static @NonNull ScimError withOffset(@NonNull ScimError error, int offset) {
        if (offset < 0 || offset > Limits.SCIM_FILTER_LENGTH.getCap())
            throw new IllegalArgumentException("SCIM expression offset exceeds its bound.");
        return new ScimError(error.statusCode, error.errorType, error.detail, offset);
    }

    /**
     * Returns a fixed redacted description.
     *
     * @return a fixed redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() {
        return "ScimError{status=" + statusCode + ", type=" + (errorType == null ? "absent" : errorType.getValue())
                + ", <redacted>}";
    }
}
