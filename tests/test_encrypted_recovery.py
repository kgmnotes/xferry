"""Recovery invariants at the public encrypted-transfer workflow boundary."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "xferry" / "data" / "static" / "ui"

SETUP = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const { installTransferServices } = require('./tests/encrypted_workflow_harness.js');
const ui = process.argv[1];
const services = new Map(), workflows = new Map();
const capability = { enabled:true,version:1,max_plaintext_size:2147483648,
  chunk_size:8388608,parallel_chunks:2,browser_decryption:true,server_decryption:true };
const app = {
  events:{SERVER_METHODS_CHANGED:'methods',LOCALE_CHANGED:'locale'},
  registerService:(name,value)=>services.set(name,value),
  service:name=>{
    if(!services.has(name))throw new Error(`missing service ${name}`);
    return services.get(name);
  },
  registerWorkflow:(name,value)=>workflows.set(name,value),on(){},
  invoke:(name,command,...args)=>workflows.get(name).commands[command](...args),
  getState:name=>workflows.get(name).getState()
};
services.set('core',{t:key=>key,formatSize:String,serverUrl:'',announceLiveRegion(){},
  getState:()=>({serverDiscoveryStatus:'ready',encryptedUploadCapabilities:capability})});
services.set('notifications',{show(){},update(){},dismiss(){}});
services.set('dialogs',{confirm:async()=>true,notice:async()=>{}});
globalThis.window={XferryApp:app};
const progress={value:0,textContent:''}, status={textContent:''};
globalThis.document={getElementById:id=>id==='encryptedUploadProgress'?progress:
  id==='encryptedTransferStatus'?status:null,querySelectorAll:()=>[]};
globalThis.indexedDB=undefined;
vm.runInThisContext(fs.readFileSync(`${ui}/encrypted-transfer-crypto.js`,'utf8'));
const storage=installTransferServices(app,ui);
function loadWorkflow(){vm.runInThisContext(fs.readFileSync(`${ui}/encrypted-transfer.js`,'utf8'));}
function response(payload,status=200){return {ok:status>=200&&status<300,status,
  headers:new Headers(),json:async()=>payload};}
function file(marker,size=5){const bytes=new Uint8Array(size).fill(marker);return {
  name:'same.bin',type:'application/octet-stream',lastModified:1,size,
  slice:(start,end)=>({arrayBuffer:async()=>bytes.slice(start,end).buffer})};}
async function waitFor(predicate){for(let i=0;i<1000;i++){
  if(predicate())return;await new Promise(resolve=>setTimeout(resolve,2));
}throw new Error('condition timed out');}
"""


def run(script: str) -> dict[str, object]:
    completed = subprocess.run(
        ["node", "-e", SETUP + script, str(UI)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_retry_keeps_ciphertext_identical_and_journals_before_transmission() -> None:
    observed = run(r"""
let record, attempts=0, durableBeforeSend=false;
const sent=[];
globalThis.fetch=async(url,options={})=>{
  if(url.includes('/chunks/')){
    attempts++;sent.push(Buffer.from(options.body).toString('hex'));
    const journal=await storage.persistence.getUpload(record.id);
    durableBeforeSend=Boolean(journal?.attemptedMacs?.['0']);
    if(attempts===1)throw new TypeError('network lost after send');
    return response({encrypted_chunk:{index:0,stored:true}});
  }
  if(url.endsWith('/complete'))return response({encrypted_file:{status:'complete'}});
  if(options.method==='PUT'){
    record={id:url.split('/').pop(),...JSON.parse(options.body),status:'partial',
      received_chunks:[],created_at:1,updated_at:1};
    return response({encrypted_upload:record});
  }
  return response({encrypted_upload:record});
};
loadWorkflow();
(async()=>{
  const result=await app.invoke('encrypted-transfer','start',{
    file:file(7),password:'audit-only-test-password'
  });
  process.stdout.write(JSON.stringify({result,attempts,identical:sent[0]===sent[1],durableBeforeSend}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert observed["attempts"] == 2
    assert observed["identical"] is True
    assert observed["durableBeforeSend"] is True
    assert observed["result"]["status"] == "complete"  # type: ignore[index]


def test_resume_rejects_changed_unacknowledged_block_before_aes_nonce_reuse() -> None:
    observed = run(r"""
let record, sendCount=0;
globalThis.fetch=async(url,options={})=>{
  if(url.includes('/chunks/')){sendCount++;throw new TypeError('offline');}
  if(url.endsWith('/complete'))return response({encrypted_file:{status:'complete'}});
  if(options.method==='PUT'){
    record={id:url.split('/').pop(),...JSON.parse(options.body),status:'partial',
      received_chunks:[],created_at:1,updated_at:1};
    return response({encrypted_upload:record});
  }
  return response({encrypted_upload:record});
};
loadWorkflow();
(async()=>{
  const original=app.invoke('encrypted-transfer','start',{
    file:file(7),password:'audit-only-test-password'
  });
  original.catch(()=>{});
  await waitFor(()=>sendCount>0);
  await app.invoke('encrypted-transfer','pause');await original.catch(()=>{});
  const before=sendCount;
  // A fresh workflow models reload while browser journal remains durable.
  loadWorkflow();
  let error='';
  try{
    await app.invoke('encrypted-transfer','resume',{
      record,file:file(8),password:'audit-only-test-password'
    });
  }
  catch(e){error=e.message;}
  process.stdout.write(JSON.stringify({error,before,after:sendCount,
    journal:await storage.persistence.getUpload(record.id)
  }));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert "match" in str(observed["error"]).lower()
    assert observed["after"] == observed["before"]
    assert observed["journal"]["attemptedMacs"]["0"]  # type: ignore[index]


def test_legacy_partial_without_nonce_journal_cannot_be_resumed() -> None:
    observed = run(r"""
const codec=app.service('encrypted-transfer-crypto');
(async()=>{
  const manifest={version:1,fileId:'00112233445566778899aabbccddeeff',plaintextSize:5,
    chunkSize:8388608,chunkCount:1,salt:new Uint8Array(16),noncePrefix:new Uint8Array(8)};
  const keys=await codec.deriveKeys('audit-only-test-password',manifest.salt,manifest.fileId);
  const encrypted=await codec.encryptMetadata({
    name:'same.bin',content_type:'application/octet-stream',last_modified_ms:1
  },keys.contentKey,manifest);
  const record={id:manifest.fileId,version:1,plaintext_size:5,chunk_size:8388608,chunk_count:1,
    salt:codec.encodeBase64Url(manifest.salt),nonce_prefix:codec.encodeBase64Url(manifest.noncePrefix),
    encrypted_metadata:codec.encodeBase64Url(encrypted),status:'partial',received_chunks:[]};
  let writes=0;
  globalThis.fetch=async(url,options={})=>{if(options.method==='PUT'||options.method==='POST')writes++;
    return response({encrypted_upload:record});};
  loadWorkflow();let error='';
  try{
    await app.invoke('encrypted-transfer','resume',{
      record,file:file(7),password:'audit-only-test-password'
    });
  }catch(e){error=e.message;}
  process.stdout.write(JSON.stringify({error,writes}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert "journal" in str(observed["error"]).lower()
    assert observed["writes"] == 0


DOWNLOAD_SETUP = r"""
const codec=app.service('encrypted-transfer-crypto');
async function completedFile(){
  const manifest={version:1,fileId:'00112233445566778899aabbccddeeff',plaintextSize:8388613,
    chunkSize:8388608,chunkCount:2,salt:new Uint8Array(16),noncePrefix:new Uint8Array(8)};
  const keys=await codec.deriveKeys('audit-only-test-password',manifest.salt,manifest.fileId);
  manifest.encryptedMetadata=await codec.encryptMetadata({
    name:'download.bin',content_type:'',last_modified_ms:1
  },keys.contentKey,manifest);
  const record={id:manifest.fileId,version:1,plaintext_size:manifest.plaintextSize,
    chunk_size:8388608,chunk_count:2,
    salt:codec.encodeBase64Url(manifest.salt),nonce_prefix:codec.encodeBase64Url(manifest.noncePrefix),
    encrypted_metadata:codec.encodeBase64Url(manifest.encryptedMetadata),status:'complete',received_chunks:[]};
  const ciphertext=await Promise.all([0,1].map(index=>codec.encryptChunk(
    new Uint8Array(index===0?8388608:5).fill(index+7),keys.contentKey,manifest,index)));
  return {record,ciphertext};
}
function outputFile(options={}){
  const state={bytes:0,closed:false,aborted:false,firstBytes:[]};
  return {state,createWritable:async()=>({
    async write(bytes){
      state.bytes+=bytes.byteLength;state.firstBytes.push(bytes[0]);options.onWrite?.(bytes);
    },
    async close(){
      if(options.failClose)throw new Error('destination disk unavailable');state.closed=true;
    },
    async abort(){state.aborted=true;}
  })};
}
function chunkResponse(bytes){return new Response(bytes,{status:200});}
async function unlock(record){await app.invoke('encrypted-transfer','refresh');
  return app.invoke('encrypted-transfer','unlock',{
    id:record.id,password:'audit-only-test-password'
  });}
"""


def test_download_reload_replays_cached_blocks_and_fetches_only_missing_chunks() -> None:
    observed = run(
        DOWNLOAD_SETUP
        + r"""
(async()=>{
  const {record,ciphertext}=await completedFile();let offline=true;
  const calls=[0,0];
  globalThis.fetch=async(url)=>{
    if(url.includes('/chunks/')){const index=Number(url.split('/').pop());calls[index]++;
      if(index===1&&offline)throw new TypeError('network disconnected');
      return chunkResponse(ciphertext[index]);}
    return response(url.endsWith('/encrypted-uploads')?
      {encrypted_uploads:[]}:{encrypted_files:[record]});
  };
  loadWorkflow();await unlock(record);
  const first=outputFile();
  const pending=app.invoke('encrypted-transfer','download-client',{id:record.id,fileHandle:first});
  pending.catch(()=>{});
  await waitFor(()=>calls[1]>0);
  const during=app.getState('encrypted-transfer');
  await app.invoke('encrypted-transfer','pause');await pending;
  const saved=await storage.persistence.getDownload(record.id);
  const before=calls[0];offline=false;
  loadWorkflow();await unlock(record);const second=outputFile();
  await app.invoke('encrypted-transfer','download-client',{id:record.id,fileHandle:second});
  process.stdout.write(JSON.stringify({during,saved,before,after:calls[0],
    first:first.state,second:second.state,
    remaining:await storage.persistence.getDownload(record.id),
    cacheBytes:(await storage.persistence.cacheStats()).bytes
  }));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
"""
    )
    assert observed["during"]["progressReceived"] == 1  # type: ignore[index]
    assert observed["during"]["bytesDone"] >= 8388608  # type: ignore[index]
    assert observed["saved"]["cachedIndexes"] == [0]  # type: ignore[index]
    assert observed["before"] == observed["after"] == 1
    assert observed["first"]["aborted"] is True  # type: ignore[index]
    assert observed["second"] == {
        "bytes": 8388613,
        "closed": True,
        "aborted": False,
        "firstBytes": [7, 8],
    }
    assert observed["remaining"] is None
    assert observed["cacheBytes"] == 0


def test_failed_output_close_preserves_cache_and_corrupt_cache_block_is_refetched() -> None:
    observed = run(
        DOWNLOAD_SETUP
        + r"""
(async()=>{
  const {record,ciphertext}=await completedFile();const calls=[0,0];
  globalThis.fetch=async(url)=>{
    if(url.includes('/chunks/')){
      const index=Number(url.split('/').pop());calls[index]++;
      return chunkResponse(ciphertext[index]);
    }
    return response(url.endsWith('/encrypted-uploads')?
      {encrypted_uploads:[]}:{encrypted_files:[record]});
  };
  loadWorkflow();await unlock(record);let error='';
  const first=outputFile({failClose:true});
  try{
    await app.invoke('encrypted-transfer','download-client',{id:record.id,fileHandle:first});
  }catch(e){error=e.message;}
  const saved=await storage.persistence.getDownload(record.id);
  storage.chunks.get(`${record.id}/0`)[0]^=1;
  loadWorkflow();await unlock(record);const second=outputFile();
  await app.invoke('encrypted-transfer','download-client',{id:record.id,fileHandle:second});
  process.stdout.write(JSON.stringify({error,saved,calls,first:first.state,second:second.state,
    remaining:await storage.persistence.getDownload(record.id)}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
"""
    )
    assert "disk" in str(observed["error"])
    assert observed["saved"]["cachedIndexes"] == [0, 1]  # type: ignore[index]
    assert observed["calls"] == [2, 1]
    assert observed["first"]["aborted"] is True  # type: ignore[index]
    assert observed["second"]["closed"] is True  # type: ignore[index]
    assert observed["remaining"] is None


def test_journal_commit_failure_prevents_chunk_encryption_and_transmission() -> None:
    observed = run(r"""
let encrypted=0,sent=0,saves=0;
const codec=app.service('encrypted-transfer-crypto'),old=codec.encryptChunk;
codec.encryptChunk=async(...args)=>{encrypted++;return old(...args);};
const save=storage.persistence.saveUpload;
storage.persistence.saveUpload=async record=>{
  if(++saves===2)throw new Error('durability unavailable');return save(record);
};
globalThis.fetch=async(url,options={})=>{
  if(url.includes('/chunks/'))sent++;
  return response({encrypted_upload:{id:url.split('/').pop()}});
};
loadWorkflow();
(async()=>{let error='';try{
  await app.invoke('encrypted-transfer','start',{
    file:file(7),password:'audit-only-test-password'
  });
}catch(e){error=e.message;}
  process.stdout.write(JSON.stringify({error,encrypted,sent}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert "durability" in str(observed["error"])
    assert observed["encrypted"] == observed["sent"] == 0


def test_in_memory_resume_reads_newer_cross_tab_nonce_journal_before_encrypting() -> None:
    observed = run(r"""
let record,sends=0;
globalThis.fetch=async(url,options={})=>{
  if(url.includes('/chunks/')){sends++;throw new TypeError('acknowledgement lost');}
  if(options.method==='PUT')record={id:url.split('/').pop(),...JSON.parse(options.body),status:'partial',received_chunks:[]};
  return response({encrypted_upload:record});
};
const originalFile={name:'same.bin',type:'',lastModified:1,size:16777221,
  slice:(start,end)=>({arrayBuffer:async()=>new Uint8Array(end-start).fill(7).buffer})};
loadWorkflow();
(async()=>{
  const original=app.invoke('encrypted-transfer','start',{
    file:originalFile,password:'audit-only-test-password'
  });original.catch(()=>{});
  await waitFor(()=>sends>=2);await app.invoke('encrypted-transfer','pause');await original;
  const codec=app.service('encrypted-transfer-crypto');
  const manifest={version:1,fileId:record.id,plaintextSize:record.plaintext_size,
    chunkSize:8388608,chunkCount:3,
    salt:codec.decodeBase64Url(record.salt),noncePrefix:codec.decodeBase64Url(record.nonce_prefix)};
  const keys=await codec.deriveKeys('audit-only-test-password',manifest.salt,manifest.fileId);
  const otherMac=codec.encodeBase64Url(await codec.computeResumeMac(
    new Uint8Array(5).fill(8),keys.resumeKey,manifest,2
  ));
  const journal=await storage.persistence.getUpload(record.id);
  // Another tab acquired/released the lock and attempted the previously untouched suffix.
  await storage.persistence.saveUpload({
    ...journal,attemptedMacs:{...journal.attemptedMacs,2:otherMac}
  });
  const before=sends;let error='';
  const resumed=app.invoke('encrypted-transfer','resume');resumed.catch(()=>{});
  // Old unsafe workflow sends different bytes here; interrupt its retries deterministically.
  await waitFor(()=>app.getState('encrypted-transfer').phase==='error'||sends>before);
  if(sends>before)await app.invoke('encrypted-transfer','pause');
  try{await resumed;}catch(e){error=e.message;}
  process.stdout.write(JSON.stringify({error,before,after:sends,
    newerMac:(await storage.persistence.getUpload(record.id)).attemptedMacs['2'],otherMac}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert "match" in str(observed["error"]).lower()
    assert observed["after"] == observed["before"]
    assert observed["newerMac"] == observed["otherMac"]


def test_large_file_queue_is_sequential_and_keeps_only_two_chunk_requests_active() -> None:
    observed = run(r"""
let nextId=0,activeChunks=0,peak=0,activeFile='',crossedFiles=false;
const ids=[],sentByFile={},keys=[];
services.set('encrypted-transfer-crypto',{
  chunkSize:8388608,randomBytes:length=>new Uint8Array(length).fill(++nextId),
  encodeBase64Url:bytes=>Buffer.from(bytes).toString('base64url'),
  deriveKeys:async()=>{
    const value={contentKey:new Uint8Array(32).fill(7),resumeKey:new Uint8Array(32).fill(8)};
    keys.push(value);return value;
  },
  encryptMetadata:async()=>new Uint8Array(16),computeResumeMac:async()=>new Uint8Array(32),
  encryptChunk:async()=>new Uint8Array(16),
});
globalThis.fetch=async(url,options={})=>{
  const parts=url.split('/'),id=parts[3];
  if(url.endsWith('/encrypted-uploads'))return response({encrypted_uploads:[]});
  if(url.includes('/chunks/')){
    if(activeChunks&&activeFile!==id)crossedFiles=true;
    activeFile=id;activeChunks++;peak=Math.max(peak,activeChunks);
    await new Promise(resolve=>setImmediate(resolve));activeChunks--;
    sentByFile[id]=(sentByFile[id]||0)+1;
    return response({encrypted_chunk:{index:Number(parts.pop()),stored:true}});
  }
  if(url.endsWith('/complete'))return response({encrypted_file:{status:'complete'}});
  ids.push(id);return response({encrypted_upload:{id}});
};
const files=[...Array(5)].map((_,index)=>({
  name:`large-${index}.bin`,type:'',lastModified:1,size:2147483648,
  slice:(start,end)=>({arrayBuffer:async()=>new ArrayBuffer(end-start)})}));
files.push({name:'tail.bin',type:'',lastModified:1,size:1,
  slice:()=>({arrayBuffer:async()=>new ArrayBuffer(1)})});
loadWorkflow();
(async()=>{
  const result=await app.invoke('encrypted-transfer','enqueue',{
    files,password:'audit-only-test-password'
  });
  process.stdout.write(JSON.stringify({result,peak,crossedFiles,count:ids.length,
    total:files.reduce((sum,value)=>sum+value.size,0),
    chunkCounts:Object.values(sentByFile),state:app.getState('encrypted-transfer'),
    wiped:keys.every(value=>value.contentKey.every(byte=>byte===0)&&value.resumeKey.every(byte=>byte===0))}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert observed["result"]["status"] == "complete"  # type: ignore[index]
    assert observed["total"] == 10737418241
    assert observed["count"] == 6
    assert observed["peak"] == 2
    assert observed["crossedFiles"] is False
    assert observed["chunkCounts"] == [256, 256, 256, 256, 256, 1]
    assert observed["wiped"] is True
    assert len(observed["state"]["queue"]) == 6  # type: ignore[index]


def test_resume_recognizes_completed_file_after_completion_acknowledgement_is_lost() -> None:
    observed = run(r"""
let record,completed=false,completionAttempts=0,chunkSends=0;
globalThis.fetch=async(url,options={})=>{
  if(url.includes('/chunks/')){chunkSends++;record.received_chunks=[{
    index:0,resume_mac:options.headers['X-XFerry-Chunk-MAC']
  }];
    return response({encrypted_chunk:{index:0,stored:true}});}
  if(url.endsWith('/complete')){
    completed=true;completionAttempts++;throw new TypeError('completion ACK lost');
  }
  if(options.method==='PUT'){
    record={id:url.split('/').pop(),...JSON.parse(options.body),status:'partial',received_chunks:[]};
    return response({encrypted_upload:record});
  }
  if(url.includes('/encrypted-files/'))return response({
    encrypted_file:{...record,status:'complete'}
  });
  if(completed)return response({error:{message:'Encrypted resource not found'}},404);
  return response({encrypted_upload:record});
};
loadWorkflow();
(async()=>{
  const first=app.invoke('encrypted-transfer','start',{
    file:file(7),password:'audit-only-test-password'
  });first.catch(()=>{});
  await waitFor(()=>completionAttempts>0);
  await app.invoke('encrypted-transfer','pause');await first;
  const result=await app.invoke('encrypted-transfer','resume');
  process.stdout.write(JSON.stringify({result,chunkSends,phase:app.getState('encrypted-transfer').phase,
    journal:await storage.persistence.getUpload(record.id)}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert observed["result"]["status"] == "complete"  # type: ignore[index]
    assert observed["chunkSends"] == 1
    assert observed["phase"] == "complete"
    assert observed["journal"] is None


def test_server_decrypt_cannot_overlap_an_active_browser_transfer() -> None:
    observed = run(
        DOWNLOAD_SETUP
        + r"""
(async()=>{
  const {record,ciphertext}=await completedFile();let sent=0,disclosed=0;
  globalThis.fetch=async(url,options={})=>{
    if(url.endsWith('/decrypt')){disclosed++;return chunkResponse(new Uint8Array(5));}
    if(url.includes('/chunks/')){sent++;throw new TypeError('offline');}
    return response(url.endsWith('/encrypted-uploads')?
      {encrypted_uploads:[]}:{encrypted_files:[record]});
  };
  loadWorkflow();await unlock(record);
  const pending=app.invoke('encrypted-transfer','download-client',{
    id:record.id,fileHandle:outputFile()
  });pending.catch(()=>{});
  await waitFor(()=>sent>0);let error='';
  try{
    await app.invoke('encrypted-transfer','download-server',{
      id:record.id,fileHandle:outputFile()
    });
  }catch(e){error=e.message;}
  await app.invoke('encrypted-transfer','pause');await pending;
  process.stdout.write(JSON.stringify({error,disclosed}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
"""
    )
    assert "active" in str(observed["error"]).lower()
    assert observed["disclosed"] == 0


def test_cancel_after_pause_commits_pending_deletion_before_offline_request() -> None:
    observed = run(r"""
let record,sends=0,deletes=0;
globalThis.fetch=async(url,options={})=>{
  if(options.method==='DELETE'){deletes++;return response({error:{message:'offline'}},403);}
  if(url.includes('/chunks/')){sends++;throw new TypeError('offline');}
  if(options.method==='PUT'){
    record={id:url.split('/').pop(),...JSON.parse(options.body),status:'partial',received_chunks:[]};
  }
  return response({encrypted_upload:record});
};
loadWorkflow();
(async()=>{
  const first=app.invoke('encrypted-transfer','start',{
    file:file(7),password:'audit-only-test-password'
  });first.catch(()=>{});
  await waitFor(()=>sends>0);await app.invoke('encrypted-transfer','pause');await first;
  let error='';try{await app.invoke('encrypted-transfer','cancel');}catch(e){error=e.message;}
  const journal=await storage.persistence.getUpload(record.id);
  process.stdout.write(JSON.stringify({error,deletes,journal,pending:app.getState('encrypted-transfer').pendingDeletes}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert observed["deletes"] == 1
    assert observed["journal"]["status"] == "pending-delete"  # type: ignore[index]
    assert observed["journal"]["id"] in observed["pending"]  # type: ignore[index,operator]


def test_initial_create_outage_can_resume_without_reencrypting_metadata() -> None:
    observed = run(r"""
let record,creates=0,offline=true,metadataEncryptions=0;
const codec=app.service('encrypted-transfer-crypto'),encrypt=codec.encryptMetadata;
codec.encryptMetadata=async(...args)=>{metadataEncryptions++;return encrypt(...args);};
globalThis.fetch=async(url,options={})=>{
  if(url.includes('/chunks/'))return response({encrypted_chunk:{index:0,stored:true}});
  if(url.endsWith('/complete'))return response({encrypted_file:{status:'complete'}});
  if(options.method==='PUT'){
    creates++;if(offline)throw new TypeError('initial connection failed');
    record={id:url.split('/').pop(),...JSON.parse(options.body),status:'partial',received_chunks:[]};
    return response({encrypted_upload:record});
  }
  return response({error:{message:'not found'}},404);
};
loadWorkflow();
(async()=>{
  const first=app.invoke('encrypted-transfer','start',{
    file:file(7),password:'audit-only-test-password'
  });first.catch(()=>{});
  await waitFor(()=>creates>0);await app.invoke('encrypted-transfer','pause');await first;
  offline=false;const result=await app.invoke('encrypted-transfer','resume');
  process.stdout.write(JSON.stringify({result,creates,metadataEncryptions}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert observed["result"]["status"] == "complete"  # type: ignore[index]
    assert observed["creates"] == 2
    assert observed["metadataEncryptions"] == 1


def test_ui_resume_followed_by_pause_keeps_paused_status_without_list_refresh_error() -> None:
    observed = run(r"""
let record,sends=0;
const listeners=new Map();
const resumeButton={addEventListener:(event,listener)=>listeners.set(event,listener)};
const originalGet=document.getElementById;
document.getElementById=id=>id==='encryptedUploadResumeBtn'?resumeButton:originalGet(id);
globalThis.fetch=async(url,options={})=>{
  if(url.includes('/chunks/')){sends++;throw new TypeError('offline');}
  if(options.method==='PUT'){
    record={id:url.split('/').pop(),...JSON.parse(options.body),status:'partial',received_chunks:[]};
  }
  return response({encrypted_upload:record});
};
loadWorkflow();
(async()=>{
  const first=app.invoke('encrypted-transfer','start',{
    file:file(7),password:'audit-only-test-password'
  });first.catch(()=>{});
  await waitFor(()=>sends>0);await app.invoke('encrypted-transfer','pause');await first;
  const before=sends;
  listeners.get('click')();
  await waitFor(()=>sends>before);
  await app.invoke('encrypted-transfer','pause');
  // Allow the real UI listener's completion handler to settle.
  await new Promise(resolve=>setImmediate(resolve));
  process.stdout.write(JSON.stringify({phase:app.getState('encrypted-transfer').phase,
    status:status.textContent,resumeAvailable:!resumeButton.disabled}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert observed["phase"] == "paused"
    assert observed["resumeAvailable"] is True


def test_remote_resume_form_followed_by_pause_keeps_paused_status() -> None:
    observed = run(r"""
let record,sends=0;
globalThis.fetch=async(url,options={})=>{
  if(url.includes('/chunks/')){sends++;throw new TypeError('offline');}
  if(options.method==='PUT'){
    record={id:url.split('/').pop(),...JSON.parse(options.body),status:'partial',received_chunks:[]};
  }
  if(url.endsWith('/encrypted-uploads'))return response({encrypted_uploads:[record]});
  if(url.endsWith('/encrypted-files'))return response({encrypted_files:[]});
  return response({encrypted_upload:record});
};
loadWorkflow();
(async()=>{
  const selected=file(7);
  const first=app.invoke('encrypted-transfer','start',{
    file:selected,password:'audit-only-test-password'
  });first.catch(()=>{});
  await waitFor(()=>sends>0);await app.invoke('encrypted-transfer','pause');await first;
  // Minimal DOM boundary for the real list and form event listeners on reload.
  function element(){return {dataset:{},listeners:new Map(),focus(){},
    addEventListener(event,listener){this.listeners.set(event,listener);},
    append(){},appendChild(){},replaceChildren(){},setAttribute(){}};}
  const list=element(),form=element(),input=element(),password=element();
  input.files=[selected];password.value='audit-only-test-password';
  const nodes={encryptedPartialList:list,encryptedResumeForm:form,
    encryptedResumeFileInput:input,encryptedResumePasswordInput:password};
  const originalGet=document.getElementById;
  document.getElementById=id=>nodes[id]||originalGet(id);
  document.createElement=element;
  loadWorkflow();await app.invoke('encrypted-transfer','refresh');
  list.listeners.get('click')({target:{closest:()=>({dataset:{
    encryptedAction:'resume-remote',encryptedId:record.id
  }})}});
  const before=sends;
  form.listeners.get('submit')({preventDefault(){}});
  await waitFor(()=>sends>before);
  await app.invoke('encrypted-transfer','pause');
  await new Promise(resolve=>setImmediate(resolve));
  process.stdout.write(JSON.stringify({phase:app.getState('encrypted-transfer').phase,
    status:status.textContent}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert observed["phase"] == "paused"
