"""Browser queue admission before encryption or sending content."""

from tests.test_encrypted_recovery import run


def test_queue_rejects_aggregate_ciphertext_over_quota_before_key_derivation() -> None:
    observed = run(r"""
let derived=0,writes=0;
const codec=app.service('encrypted-transfer-crypto');
const derive=codec.deriveKeys;
codec.deriveKeys=async(...args)=>{derived++;return derive(...args);};
globalThis.fetch=async(url,options={})=>{
  if(options.method==='PUT'||options.method==='POST')writes++;
  return response({encrypted_uploads:[],storage:{used_bytes:0,quota_bytes:40,
    disk_free_bytes:1000,reserved_free_bytes:0,available_bytes:40,file_count:0,
    file_limit:4096,remaining_files:4096,max_plaintext_size:24,
    configured_max_plaintext_size:34359738368,technical_max_plaintext_size:34359738368}});
};
loadWorkflow();
(async()=>{
  let error='';
  try { await app.invoke('encrypted-transfer','enqueue',{
    files:[file(1,10),file(2,10)],password:'audit-only-test-password'
  }); } catch(e){error=e.message;}
  process.stdout.write(JSON.stringify({error,derived,writes,active:app.getState('encrypted-transfer').activeId}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert "encryptedQuotaBytesExceeded" in observed["error"]
    assert observed["derived"] == 0
    assert observed["writes"] == 0
    assert observed["active"] is None


def test_queue_rejects_empty_files_when_file_slots_are_exhausted() -> None:
    observed = run(r"""
let writes=0;
globalThis.fetch=async(url,options={})=>{
  if(options.method==='PUT'||options.method==='POST')writes++;
  return response({encrypted_uploads:[],storage:{used_bytes:0,quota_bytes:1000,
    disk_free_bytes:1000,reserved_free_bytes:0,available_bytes:1000,file_count:4096,
    file_limit:4096,remaining_files:0,max_plaintext_size:0,
    configured_max_plaintext_size:34359738368,technical_max_plaintext_size:34359738368}});
};
loadWorkflow();
(async()=>{
  let error='';
  try { await app.invoke('encrypted-transfer','enqueue',{
    files:[file(1,0)],password:'audit-only-test-password'
  }); } catch(e){error=e.message;}
  process.stdout.write(JSON.stringify({error,writes}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert "encryptedQuotaFilesExceeded" in observed["error"]
    assert observed["writes"] == 0


def test_capacity_refresh_updates_dynamic_limit_without_unlocking_existing_files() -> None:
    observed = run(r"""
const storageInfo={used_bytes:0,quota_bytes:8589934592,disk_free_bytes:10000000000,
  reserved_free_bytes:0,available_bytes:8589934592,file_count:0,file_limit:4096,
  remaining_files:4096,max_plaintext_size:8589918208,
  configured_max_plaintext_size:34359738368,technical_max_plaintext_size:34359738368};
globalThis.fetch=async(url)=>response(url.endsWith('encrypted-uploads')?
  {encrypted_uploads:[],storage:storageInfo,incomplete_ttl_seconds:604800}:{encrypted_files:[]});
loadWorkflow();
(async()=>{
  await app.invoke('encrypted-transfer','refresh');
  const state=app.getState('encrypted-transfer');
  process.stdout.write(JSON.stringify({storage:state.storage,files:state.encryptedFiles}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert observed["storage"]["max_plaintext_size"] == 8589918208
    assert observed["storage"]["remaining_files"] == 4096
    assert observed["files"] == []


def test_server_quota_race_returns_localized_reason_without_retrying_content() -> None:
    observed = run(r"""
let writes=0;
globalThis.fetch=async(url,options={})=>{
  if(options.method==='PUT')writes++;
  return response({error:{code:'storage_quota_exceeded',message:'Upload storage quota exceeded',
    details:{scope:'uploads',reason:'free_space'}}},507);
};
loadWorkflow();
(async()=>{
  let error='';
  try { await app.invoke('encrypted-transfer','start',{
    file:file(1),password:'audit-only-test-password'
  }); } catch(e){error=e.message;}
  process.stdout.write(JSON.stringify({error,writes,state:app.getState('encrypted-transfer')}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert "encryptedQuotaFreeSpaceExceeded" in observed["state"]["lastError"]
    assert observed["writes"] == 1


def test_many_files_with_large_private_metadata_can_be_listed_with_bounded_response() -> None:
    observed = run(r"""
const codec=app.service('encrypted-transfer-crypto');
const metadata=codec.encodeBase64Url(new Uint8Array(4112));
const records=Array.from({length:4096},(_,i)=>({id:i.toString(16).padStart(32,'0'),version:1,
  plaintext_size:0,ciphertext_size:0,chunk_size:8388608,chunk_count:0,
  salt:codec.encodeBase64Url(new Uint8Array(16)),
  nonce_prefix:codec.encodeBase64Url(new Uint8Array(8)),
  encrypted_metadata:metadata,status:'complete',received_chunks:[],created_at:1,updated_at:1}));
globalThis.fetch=async(url)=>new Response(JSON.stringify(url.endsWith('encrypted-files')?
  {encrypted_files:records}:{encrypted_uploads:[]}));
loadWorkflow();
(async()=>{
  await app.invoke('encrypted-transfer','refresh');
  process.stdout.write(JSON.stringify({count:app.getState('encrypted-transfer').encryptedFiles.length}));
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
""")
    assert observed["count"] == 4096
