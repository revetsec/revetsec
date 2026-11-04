// Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
// Public-API driver for the released client's ordinary server picker; no OAuth or MCP SDK calls.
const vscode=require('vscode');
const fs=require('node:fs');
exports.activate=async context=>{
 const root=process.env.REVETSEC_QUAL_ROOT;
 const config=JSON.parse(fs.readFileSync(root+'/driver-input.json','utf8'));
 const facts={stage:'ACTIVATED'};
 const write=stage=>{facts.stage=stage;fs.writeFileSync(root+'/driver-facts.json',JSON.stringify(facts),{mode:0o600});};
 try{
  write('WAITING_WORKSPACE_TRUST');
  if(!vscode.workspace.isTrusted)await new Promise(resolve=>context.subscriptions.push(vscode.workspace.onDidGrantWorkspaceTrust(resolve)));
  context.subscriptions.push(vscode.lm.registerMcpServerDefinitionProvider('revetsec-qualification',{provideMcpServerDefinitions:()=>[new vscode.McpHttpServerDefinition('Revetsec disposable qualification',vscode.Uri.parse(config.resource),{},'1')]}));
  write('WAITING_SERVER_START');
  // Listing activates lazy providers. The controller selects this test server and Start in the normal UI.
  void Promise.resolve(vscode.commands.executeCommand('workbench.mcp.listServer')).catch(()=>{});
  for(let i=0;i<120;i++){
   if(vscode.lm.tools.some(t=>t.name.endsWith('_whoami'))){write('TOOLS_AVAILABLE');return;}
   await new Promise(resolve=>setTimeout(resolve,500));
  }
  write('FAILED');
 }catch{write('FAILED');}
};
