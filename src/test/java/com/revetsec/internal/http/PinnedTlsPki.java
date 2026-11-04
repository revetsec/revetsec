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


package com.revetsec.internal.http;

import com.revetsec.testing.TestTls;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.SSLEngine;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.util.Map;
import java.util.LinkedHashMap;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import static java.util.Objects.requireNonNull;

/** Fresh TEST ONLY CA/intermediate/leaf. No system trust-store writes; every runtime key stays below target. */
final class PinnedTlsPki {
 private final @NonNull Path directory;
 private final @NonNull KeyStore serverKeys;
 private final @NonNull X509Certificate root;
 private final @NonNull X509Certificate intermediate;
 private final @NonNull X509Certificate leaf;
 private @Nullable Map<String,X509Certificate> cachedVariants;
 private X509Certificate @Nullable [] cachedAdversarial;
 private @Nullable X509Certificate cachedOversized;
 PinnedTlsPki(@NonNull Path directory,int probePort) throws Exception {
  this.directory=directory;Files.createDirectories(directory);
  this.serverKeys=TestTls.serverKeyStore();
  try(var out=Files.newOutputStream(directory.resolve("server.p12"))){this.serverKeys.store(out,"changeit".toCharArray());}
  command("-genkeypair","-alias","root","-keyalg","EC","-groupname","secp256r1","-dname","CN=Ephemeral Revetsec TEST ONLY CA",
    "-ext","BC:critical=ca:true,pathlen:1","-ext","KU:critical=keyCertSign,cRLSign","-validity","3650","-keystore","root.p12");
  command("-exportcert","-alias","root","-keystore","root.p12","-file","root.der");
  command("-genkeypair","-alias","issuer","-keyalg","EC","-groupname","secp256r1","-dname","CN=Ephemeral Revetsec TEST ONLY Intermediate",
    "-ext","BC:critical=ca:true,pathlen:0","-validity","3650","-keystore","issuer.p12");
  command("-certreq","-alias","issuer","-keystore","issuer.p12","-file","issuer.csr");
  command("-gencert","-alias","root","-keystore","root.p12","-infile","issuer.csr","-outfile","issuer.der",
    "-ext","BC:critical=ca:true,pathlen:0","-ext","KU:critical=keyCertSign,cRLSign","-validity","3650");
  command("-importcert","-noprompt","-alias","root","-keystore","issuer.p12","-file","root.der");
  command("-importcert","-noprompt","-alias","issuer","-keystore","issuer.p12","-file","issuer.der");
  command("-certreq","-alias","server","-keystore","server.p12","-file","server.csr");
  String base="http://127.0.0.1:"+probePort;
  command("-gencert","-alias","issuer","-keystore","issuer.p12","-infile","server.csr","-outfile","leaf.der",
    "-ext","BC:critical=ca:false","-ext","KU:critical=digitalSignature,keyEncipherment","-ext","EKU=serverAuth",
    "-ext","SAN=DNS:localhost,IP:127.0.0.1,DNS:metadata.revetsec.com,IP:8.8.8.8",
    "-ext","AIA=caIssuers:URI:"+base+"/issuer,ocsp:URI:"+base+"/ocsp",
    "-ext","2.5.29.31="+crlExtension(base+"/crl"),"-validity","3650");
  this.root=certificate("root.der");this.intermediate=certificate("issuer.der");this.leaf=certificate("leaf.der");
 }
 private void command(@NonNull String @NonNull ... arguments) throws Exception {
  List<String> command=new ArrayList<>();command.add(Path.of(System.getProperty("java.home"),"bin","keytool").toString());command.addAll(List.of(arguments));
  command.addAll(List.of("-storepass","changeit","-keypass","changeit"));
  Path log=this.directory.resolve("keytool.log");
  Process process=new ProcessBuilder(command).directory(this.directory.toFile()).redirectErrorStream(true).redirectOutput(log.toFile()).start();
  try {if(!process.waitFor(30,TimeUnit.SECONDS)||process.exitValue()!=0)throw new IllegalStateException("Ephemeral TEST ONLY certificate generation failed.");}
  finally {if(process.isAlive()){process.destroyForcibly();process.waitFor(10,TimeUnit.SECONDS);}}
 }
 private @NonNull X509Certificate certificate(@NonNull String name) throws Exception {
  try(InputStream input=Files.newInputStream(this.directory.resolve(name))){return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(input);}
 }
 @NonNull KeyStore trustStore() throws Exception {
  KeyStore trust=KeyStore.getInstance("PKCS12");trust.load(null,null);trust.setCertificateEntry("root",this.root);return trust;
 }
 void writeTrustStore(@NonNull Path path) throws Exception {try(var output=Files.newOutputStream(path)){trustStore().store(output,"changeit".toCharArray());}}
 @NonNull SSLContext server(boolean complete) throws Exception {
  return server(complete?new X509Certificate[]{this.leaf,this.intermediate,this.root}:new X509Certificate[]{this.leaf});
 }
 @NonNull SSLContext server(@NonNull X509Certificate @NonNull ... chain) throws Exception {
  // PKCS12 requires ordered entries; the wire fixture deliberately sends the supplied certificate bag.
  Certificate[] stored={this.leaf,this.intermediate,this.root};
  this.serverKeys.setKeyEntry("server",requireNonNull(this.serverKeys.getKey("server","changeit".toCharArray())),"changeit".toCharArray(),stored);
  KeyManagerFactory keys=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());keys.init(this.serverKeys,"changeit".toCharArray());
  X509ExtendedKeyManager original=(X509ExtendedKeyManager)keys.getKeyManagers()[0];
  X509ExtendedKeyManager wire=new X509ExtendedKeyManager(){
   @Override public String[] getClientAliases(String type,Principal[] issuers){return original.getClientAliases(type,issuers);}
   @Override public String chooseClientAlias(String[] types,Principal[] issuers,Socket socket){return original.chooseClientAlias(types,issuers,socket);}
   @Override public String[] getServerAliases(String type,Principal[] issuers){return original.getServerAliases(type,issuers);}
   @Override public String chooseServerAlias(String type,Principal[] issuers,Socket socket){return original.chooseServerAlias(type,issuers,socket);}
   @Override public String chooseEngineServerAlias(String type,Principal[] issuers,SSLEngine engine){return original.chooseEngineServerAlias(type,issuers,engine);}
   @Override public X509Certificate[] getCertificateChain(String alias){return chain.clone();}
   @Override public PrivateKey getPrivateKey(String alias){return original.getPrivateKey(alias);}
  };
  SSLContext context=SSLContext.getInstance("TLS");context.init(new javax.net.ssl.KeyManager[]{wire},null,null);return context;
 }
 @NonNull X509Certificate @NonNull [] chain(){return new X509Certificate[]{this.leaf,this.intermediate,this.root};}
 @NonNull Map<@NonNull String,@NonNull X509Certificate> variants() throws Exception {
  if(this.cachedVariants!=null)return this.cachedVariants;
  Map<String,X509Certificate> result=new LinkedHashMap<>();
  command("-genkeypair","-alias","other","-keyalg","EC","-groupname","secp256r1","-dname","CN=Other TEST ONLY CA",
    "-ext","BC:critical=ca:true,pathlen:2","-ext","KU:critical=keyCertSign,cRLSign","-validity","3650","-keystore","other.p12");
  command("-exportcert","-alias","other","-keystore","other.p12","-file","other.der");
  command("-certreq","-alias","root","-keystore","root.p12","-file","root.csr");
  command("-gencert","-alias","other","-keystore","other.p12","-infile","root.csr","-outfile","cross.der",
    "-ext","BC:critical=ca:true,pathlen:1","-ext","KU:critical=keyCertSign,cRLSign","-validity","3650");
  command("-gencert","-alias","other","-keystore","other.p12","-infile","issuer.csr","-outfile","untrusted-issuer.der",
    "-ext","BC:critical=ca:true,pathlen:0","-ext","KU:critical=keyCertSign,cRLSign","-validity","3650");
  result.put("other",certificate("other.der"));result.put("cross",certificate("cross.der"));
  result.put("untrusted-issuer",certificate("untrusted-issuer.der"));
  for(String variant:List.of("expired-issuer","non-ca","bad-usage","critical","name-constraint")) {
   List<String> args=new ArrayList<>(List.of("-gencert","-alias","root","-keystore","root.p12","-infile","issuer.csr","-outfile",variant+".der",
     "-ext",variant.equals("non-ca")?"BC:critical=ca:false":"BC:critical=ca:true,pathlen:0",
     "-ext",variant.equals("bad-usage")?"KU:critical=digitalSignature":"KU:critical=keyCertSign,cRLSign",
     "-validity",variant.equals("expired-issuer")?"1":"3650"));
   if(variant.equals("expired-issuer"))args.addAll(List.of("-startdate","-20d"));
   if(variant.equals("critical"))args.addAll(List.of("-ext","1.2.3.4:critical=0101ff"));
   if(variant.equals("name-constraint"))args.addAll(List.of("-ext","2.5.29.30:critical=300ea00c300a82086261642e74657374"));
   command(args.toArray(new String[0]));result.put(variant,certificate(variant+".der"));
  }
  for(String variant:List.of("expired-leaf","future-leaf","client-only")) {
   List<String> args=new ArrayList<>(List.of("-gencert","-alias","issuer","-keystore","issuer.p12","-infile","server.csr","-outfile",variant+".der",
     "-ext","BC:critical=ca:false","-ext","KU:critical=digitalSignature,keyEncipherment",
     "-ext",variant.equals("client-only")?"EKU=clientAuth":"EKU=serverAuth","-ext","SAN=DNS:localhost",
     "-validity",variant.equals("expired-leaf")?"1":"3650"));
   if(variant.equals("expired-leaf"))args.addAll(List.of("-startdate","-20d"));
   if(variant.equals("future-leaf"))args.addAll(List.of("-startdate","+3650d"));
   command(args.toArray(new String[0]));result.put(variant,certificate(variant+".der"));
  }
  command("-certreq","-alias","other","-keystore","other.p12","-file","other.csr");
  command("-gencert","-alias","issuer","-keystore","issuer.p12","-infile","other.csr","-outfile","sub-ca.der",
    "-ext","BC:critical=ca:true,pathlen:0","-ext","KU:critical=keyCertSign,cRLSign","-validity","3650");
  command("-gencert","-alias","other","-keystore","other.p12","-infile","server.csr","-outfile","deep-leaf.der",
    "-ext","BC:critical=ca:false","-ext","KU:critical=digitalSignature,keyEncipherment","-ext","EKU=serverAuth",
    "-ext","SAN=DNS:localhost","-validity","3650");
  command("-certreq","-alias","other","-keystore","other.p12","-dname","CN=Ephemeral Revetsec TEST ONLY Intermediate","-file","wrong-key.csr");
  command("-gencert","-alias","root","-keystore","root.p12","-infile","wrong-key.csr","-outfile","wrong-key.der",
    "-ext","BC:critical=ca:true,pathlen:0","-ext","KU:critical=keyCertSign,cRLSign","-validity","3650");
  result.put("wrong-key",certificate("wrong-key.der"));
  result.put("sub-ca",certificate("sub-ca.der"));result.put("deep-leaf",certificate("deep-leaf.der"));
  this.cachedVariants=Map.copyOf(result);return this.cachedVariants;
 }
 @NonNull X509Certificate @NonNull [] adversarial() throws Exception {
  if(this.cachedAdversarial!=null)return this.cachedAdversarial.clone();
  X509Certificate[] result=new X509Certificate[10];result[0]=this.root;
  for(int index=1;index<result.length;index++) {
   String name="cycle-"+index+".der";
   command("-gencert","-alias","root","-keystore","root.p12","-infile","root.csr","-outfile",name,
     "-ext","BC:critical=ca:true","-ext","KU:critical=keyCertSign,cRLSign",
     "-ext","1.2.3.4:critical=0201"+String.format(java.util.Locale.ROOT,"%02x",index),"-validity","3650");
   result[index]=certificate(name);
  }
  this.cachedAdversarial=result;return result.clone();
 }
 @NonNull X509Certificate oversized() throws Exception {
  if(this.cachedOversized!=null)return this.cachedOversized;
  command("-gencert","-alias","root","-keystore","root.p12","-infile","root.csr","-outfile","oversized.der",
    "-ext","BC:critical=ca:true","-ext","1.2.3.5="+"00".repeat(33000),"-validity","3650");
  this.cachedOversized=certificate("oversized.der");return this.cachedOversized;
 }
 byte @NonNull [] intermediateBytes() throws Exception {return this.intermediate.getEncoded();}
 private static @NonNull String crlExtension(@NonNull String url) {
  byte[] bytes=url.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
  return java.util.HexFormat.of().formatHex(der(0x30,der(0x30,der(0xa0,der(0xa0,der(0x86,bytes))))));
 }
 private static byte @NonNull [] der(int tag,byte @NonNull [] bytes) {
  if(bytes.length>=128)throw new IllegalArgumentException("TEST ONLY CRL URL too long.");
  ByteArrayOutputStream value=new ByteArrayOutputStream();value.write(tag);value.write(bytes.length);value.writeBytes(bytes);return value.toByteArray();
 }
}
