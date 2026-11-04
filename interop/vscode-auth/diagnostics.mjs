// Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
// Return literal categories only; untrusted messages, URLs and opaque values cannot become category names.
const known=['ERR_CERT_AUTHORITY_INVALID','ERR_CERT_COMMON_NAME_INVALID','ERR_SSL_PROTOCOL_ERROR','WRONG_VERSION_NUMBER','CERTIFICATE_VERIFY_FAILED','EPROTO','ECONNREFUSED','ECONNRESET','ENOTFOUND','ETIMEDOUT'];
export function fixedClientErrorCodes(text){
 if(typeof text!=='string'||text.length>1000000)return [];
 const result=new Set();
 for(const line of text.split('\n'))if(line.includes('fetch failed')||line.includes('Connection state: Error')){
  for(const code of known)if(line.includes(code))result.add(code);
  if(line.includes('fetch failed'))result.add('FETCH_FAILED');
 }
 return [...result];
}
