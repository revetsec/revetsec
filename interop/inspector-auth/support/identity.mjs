// Copyright 2026 Revetware LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {createHash} from 'node:crypto';
import {lstatSync,readFileSync,readdirSync,readlinkSync} from 'node:fs';
import {dirname,isAbsolute,relative,resolve,sep} from 'node:path';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const hashFile=path=>sha(readFileSync(path));
const json=value=>JSON.stringify(value,null,2)+'\n';
const fail=code=>{throw new Error(code);};
export function directoryIdentity(directory) {
  if (!lstatSync(directory).isDirectory() || lstatSync(directory).isSymbolicLink())
    fail('INSTALLED_ROOT_INVALID');
  const rows = [];
  function visit(path) {
    for (const name of readdirSync(path).sort()) {
      const absolute = resolve(path, name);
      const entry = lstatSync(absolute);
      const key = relative(directory, absolute).split(sep).join('/');
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile()) rows.push([key, 'file', hashFile(absolute)]);
      else if (entry.isSymbolicLink()) {
        const target = readlinkSync(absolute);
        const relativeTarget = relative(directory, resolve(dirname(absolute), target));
        if (isAbsolute(target) || relativeTarget === '..' || relativeTarget.startsWith(`..${sep}`))
          fail('INSTALLED_SYMLINK_ESCAPE');
        rows.push([key, 'link', target]);
      } else fail('INSTALLED_ENTRY_INVALID');
    }
  }
  visit(directory);
  return { files: rows.length, sha256: sha(json(rows)) };
}

export function verifyDependencyPins(packageBytes,lockBytes,pins) {
  if(sha(packageBytes)!==pins.packageSha256||sha(lockBytes)!==pins.lockSha256)fail('DEPENDENCY_PIN_DRIFT');
  const lock=JSON.parse(lockBytes);
  if(lock.lockfileVersion!==3||lock.packages['node_modules/@modelcontextprotocol/inspector']?.version!=='2.9.0'
      ||lock.packages['node_modules/@modelcontextprotocol/inspector']?.integrity!==pins.integrity)
    fail('DEPENDENCY_IDENTITY_INVALID');
  for(const [name,value]of Object.entries(lock.packages))
    if(name!==''&&(!value.resolved?.startsWith('https://registry.npmjs.org/')
        ||!/^sha512-[A-Za-z0-9+/]+=*$/.test(value.integrity)))fail('DEPENDENCY_SOURCE_INVALID');
}
