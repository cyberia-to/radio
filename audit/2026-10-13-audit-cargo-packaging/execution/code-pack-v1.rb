require 'json';require 'digest';require 'fileutils';require 'open3'
r='/Users/master/cyber/radio-bao-bounded-proof';prefix='audit/2026-10-13-audit-cargo-packaging';a=r+'/'+prefix;out='/tmp/radio-audit-cargo-packaging-code-v1';base='ce0fb312faa8770e80efe9afa864106ae6b51552'
raise 'exists' if File.exist?(out);FileUtils.mkdir_p(out+'/inputs');rows=[];context=''.b
add=->(label,body,binding){i=rows.length+1;sha=Digest::SHA256.hexdigest(body);head="\n===== #{format('%03d',i)} BEGIN #{label} | #{body.bytesize} bytes | SHA256 #{sha} =====\n";tail="\n===== #{format('%03d',i)} END #{label} =====\n";context<<head;offset=context.bytesize;context<<body<<tail;local="inputs/#{format('%03d',i)}.txt";File.binwrite(out+'/'+local,body);rows<<{label:label,bytes:body.bytesize,sha256:sha,offset:offset,header:head,footer:tail,local:local,binding:binding}}
owned=->(p){add.call(p,File.binread(r+'/'+p),{kind:'owned',path:p})}
evidence=->(p){owned.call(prefix+'/'+p)}
brief=<<~TEXT
  Fresh CODE review of an approved packaging-only fix at exact Radio parent ce0fb312faa8770e80efe9afa864106ae6b51552.
  PLAN v2 APPROVE raw and full result are supplied. Seven archived Cargo.toml bodies are renamed losslessly;
  three replay entries become thin wrappers around preserved exact originals. One shared Nu staging helper
  reconstructs historical logical names only in unique disposable directories. No production Rust, normal
  manifest/lock, version, specification, license, BAO API or Kadek pin change. Parent owns final merge.

  Review failure/collision handling, byte/hash preservation, original CLI/default semantics, explicit nonzero
  child handling, complete-tree source allowlist and the causally controlled Git-consumer differential.
  A wrapper-v1 error path omitted the retained-stage notice because Nu terminated at child nonzero; final
  wrappers use complete plus print --no-newline for both streams and exact exit_code. A status-77 literal
  control verifies this. Earlier passing/failing epochs remain separate. Temporary pair setup v1 failed at
  bare-index deletion; v2 was deliberately interrupted on wrapper change; v3 completed both arms. No green
  assertion is made from either earlier attempt. Historical --live HEAD failures remain required failures.

  Fresh isolated local-Git ce0/candidate lock, metadata, debug and release controls reproduce four duplicate
  warnings in the parent and zero candidate warnings. External historical manifest unchanged at three
  points. Reader stdout identical across all four runs and earlier frozen HTTPS control. 63 exact crate
  source tuples and normalized three-node graph match; 34 explicit parsed-JSON substitutions per arm.
  The incremental temporary candidate e22c5b47 is a local measured witness, never an origin/release input.
  Later final audit/report additions are outside its tree; its 14 final packaging files are separately
  frozen and match the reviewed live files. No new Cargo.toml basename may exist under audit.

  Supplied in full: all changed executable packaging scripts, seven archived manifest bodies, all three
  original replay contracts, approved PLAN and response, raw approval, execution report, exact independent
  reader, final control orchestrators, raw paired command receipts/streams, explicit identity maps and
  replay code. The current BAO kernels and unrelated runtime Rust are unchanged and omitted. Also omitted:
  binary carrier bodies (exact manifest/hash-retained support), whole historical capsules, complete source
  snapshots/caches/build output, old full vendor contexts, large lock/metadata snapshots beyond the two
  exact current metadata outputs, and final noncritical evidence-copy bookkeeping. Their identities remain
  indexed in capsule files.json; the reviewer has not been supplied those omitted bodies. Neither this
  review nor the focused controls refresh previous broad red gates, rung or last-tag acceptance. Review
  only this packaging change; no release claim. The codepack verifier and outer evidence verifier require
  exact historical Git objects; neither claims cache-free Cargo reproduction or archive-only source replay.
TEXT
add.call('CODE review scope and indexed omissions',brief,{kind:'brief'})
%w[plan.md response-v1.md execution.md research.md].each{|p|owned.call('.claude/tasks/audit-cargo-packaging/'+p)}
%w[README.md execution/source-freeze.json].each{|p|evidence.call(p)}
JSON.parse(File.read(a+'/execution/source-freeze.json')).each{|f|owned.call(f['path'])}
%w[Cargo.toml cyber-bao/Cargo.toml LICENSE-MIT LICENSE-APACHE].each do |p|
 b,e,s=Open3.capture3('git','-C',r,'show',base+':'+p,binmode:true);raise e unless s.success?;add.call(p,b,{kind:'git',revision:base,path:p})
end
%w[review/plan-v2/result.md review/plan-v2/stdout.json review/plan-v2/invocation.json review/plan-v2/completion.json inputs/source.json inputs/renames.json inputs/historical-index-bindings.json inputs/registry.json inputs/registry-radio.txt].each{|p|evidence.call(p)}
%w[execution/staging-tests-v2.rb execution/child-exit-v1.rb execution/pair-v3.rb execution/metadata-v1.rb pair/frozen/reader_probe.rs controls/staging-v2/results.json controls/child-exit-v1/result.json pair/snapshot.json pair/results.json pair/external-manifest.json pair/metadata-comparison.json pair/tools.json].each{|p|evidence.call(p)}
%w[parent candidate].each{|arm|%w[lock metadata debug release].each{|name|%w[json stdout stderr].each{|ext|evidence.call('pair/'+arm+'/'+name+'.'+ext)}}}
%w[research-after-v2 proof-after-v2 code-input-after-v1 research-live-after-v2 proof-live-after-v2 staging-tests-v2 child-exit-v1 pair-run-v3 metadata-v1].each{|name|%w[json stdout stderr].each{|ext|evidence.call('records/'+name+'.'+ext)}}
evidence.call('verify.nu')
manifest={parent:base,context_bytes:context.bytesize,context_sha256:Digest::SHA256.hexdigest(context),sections:rows}
File.binwrite(out+'/context.txt',context);File.write(out+'/manifest.json',JSON.pretty_generate(manifest)+"\n")
FileUtils.cp(a+'/files.json',out+'/support-files.json');FileUtils.cp(a+'/execution/source-freeze.json',out+'/source-freeze.json')
puts JSON.generate(path:out,bytes:context.bytesize,sha256:manifest[:context_sha256],sections:rows.length)
