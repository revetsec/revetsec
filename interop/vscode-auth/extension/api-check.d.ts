// Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
// Narrow Node I/O declarations; VS Code calls use the release's unmodified public vscode.d.ts.
declare module 'node:fs' {
  export function readFileSync(path: string, encoding: 'utf8'): string;
  export function writeFileSync(path: string, value: string, options?: {mode?: number}): void;
}
declare const process: {env: Record<string, string>};
