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
import javax.net.ssl.KeyManagerFactory;
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
  Certificate[] chain=complete?new Certificate[]{this.leaf,this.intermediate,this.root}:new Certificate[]{this.leaf};
  this.serverKeys.setKeyEntry("server",requireNonNull(this.serverKeys.getKey("server","changeit".toCharArray())),"changeit".toCharArray(),chain);
  KeyManagerFactory keys=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());keys.init(this.serverKeys,"changeit".toCharArray());
  SSLContext context=SSLContext.getInstance("TLS");context.init(keys.getKeyManagers(),null,null);return context;
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
