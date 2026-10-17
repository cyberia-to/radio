require 'json'
require 'digest'
require 'open3'
require 'fileutils'
require 'time'
ROOT='/Users/master/cyber/radio-bao-bounded-proof'
A=ROOT+'/audit/2026-10-12-bao-proof-research'
REVS={'radio'=>'a96d86e28d384cdf656aadc4282c78c0c170c102','hemera'=>'d5f0a09539360934fb32db9b2e15a91995607db6','kadek'=>'4d9ca9ab3498238b9c1e03f6d6f160e1ec729912','soft3'=>'18fd6b22ec45725aa776e37d377c5a75aeeaf553'}
REPOS={'radio'=>ROOT,'hemera'=>'/Users/master/cyber/hemera','kadek'=>'/Users/master/cyber/kadek','soft3'=>'/Users/master/cyber/soft3'}
def blob(repo,rev,path)
 s,e,p=Open3.capture3('git','-C',REPOS.fetch(repo),'show',rev+':'+path,binmode:true)
 raise e unless p.success?;s
end
def sha(s);Digest::SHA256.hexdigest(s);end
def write(path,value); File.write(A+'/'+path,JSON.pretty_generate(value)+"\n");end
def identity(path,bytes); {path:path,bytes:bytes.bytesize,sha256:sha(bytes)};end
initial=JSON.parse(File.read(A+'/inputs.json'))
initial['git_inputs'].each{|f|s=blob(f['repository'],f['revision'],f['path']);raise f.inspect unless s.bytesize==f['bytes'] && sha(s)==f['sha256']}
[initial['probe_inputs'],JSON.parse(File.read(A+'/primary-inputs.json'))['files']].flatten.each{|f|s=File.binread(A+'/'+f['path']);raise f.inspect unless s.bytesize==f['bytes'] && sha(s)==f['sha256']}
paths={
 'radio'=>%w[Cargo.lock Makefile.toml .config/nextest.toml .github/workflows/ci.yml .github/workflows/tests.yaml cyber-bao/src/lib.rs cyber-bao/src/tree.rs cyber-bao/src/io/slice.rs cyber-bao/tests/root_policy.rs cyber-bao/tests/slice_traversal.rs iroh-blobs/Cargo.toml particle/Cargo.toml radio-cli/Cargo.toml tests/integration/Cargo.toml iroh-docs/Cargo.toml iroh-blobs/src/api/blobs.rs iroh-blobs/src/api/blobs/export_pairs.rs particle/src/main.rs radio-cli/src/main.rs],
 'hemera'=>%w[specs/tree.md specs/capacity.md specs/encoding.md rs/src/params.rs rs/src/lib.rs rs/src/field.rs rs/src/encoding.rs rs/src/sponge.rs rs/src/tree.rs],
 'kadek'=>%w[Cargo.toml Cargo.lock kadek-ifac/Cargo.toml kadek-ifac/src/provenance.rs kadek-ifac/src/provenance/anchor.rs specs/runtime.md],
 'soft3'=>%w[release/components.toml]
}
inputs=[]
paths.each{|repo,list|list.each{|p|s=blob(repo,REVS[repo],p);inputs << identity(p,s).merge(repository:repo,revision:REVS[repo])}}
write('support-inputs.json',inputs)
excerpts=[
 ['hemera','specs/tree.md',8,113,'hemera-tree-contract.md'],
 ['hemera','specs/encoding.md',29,42,'hemera-output-contract.md'],
 ['hemera','specs/capacity.md',11,48,'hemera-capacity-contract.md'],
 ['hemera','rs/src/field.rs',10,44,'hemera-field.rs'],
 ['hemera','rs/src/encoding.rs',47,79,'hemera-encoding.rs'],
 ['hemera','rs/src/sponge.rs',22,43,'hemera-hash.rs'],
 ['hemera','rs/src/tree.rs',95,148,'hemera-parent.rs'],
 ['hemera','rs/src/tree.rs',870,884,'hemera-kernel-aliases.rs'],
 ['soft3','release/components.toml',250,260,'radio-rung.toml'],
 ['soft3','release/components.toml',653,662,'kadek-rung.toml'],
 ['radio','iroh-blobs/src/api/blobs.rs',1011,1020,'export-pair.rs'],
 ['radio','iroh-blobs/src/api/blobs.rs',14,38,'export-test-boundary.rs'],
 ['kadek','specs/runtime.md',36,57,'kadek-authority.md']
]
FileUtils.mkdir_p(A+'/primary')
rows=excerpts.map{|repo,path,first,last,name|s=blob(repo,REVS[repo],path);part=s.lines[first-1..last-1].join;local='primary/'+name;File.binwrite(A+'/'+local,part);identity(local,part).merge(repository:repo,revision:REVS[repo],source:path,source_sha256:sha(s),first:first,last:last)}
write('excerpts.json',rows)
FileUtils.mkdir_p(A+'/prerequisite')
pr='/Users/master/cyber/radio-bao-bounded-traversal'
prrows=%w[cyber-bao/src/traversal.rs .claude/tasks/bao-bounded-traversal/plan.md .claude/tasks/bao-bounded-traversal/literal-cases.md].map{|p|s=File.binread(pr+'/'+p);n=File.basename(p);File.binwrite(A+'/prerequisite/'+n,s);identity('prerequisite/'+n,s).merge(source:pr+'/'+p,status:'unmerged frozen candidate; historical after bridge')}
write('prerequisite-candidate.json',{parent:REVS['radio'],selected_source_digest:'53f29b5b1cf4d609ecb98c7b482198f87160fb56fdb229466bff8f33568a90eb',files:prrows})
fixtures=Dir[A+'/fixtures/*.bin'].sort.map{|p|s=File.binread(p);release=File.binread('/tmp/radio-bao-proof-primary-release-fixtures/'+File.basename(p));raise p unless s==release;identity(p.delete_prefix(A+'/'),s).merge(kind:File.basename(p).start_with?('synthetic') ? 'synthetic parent encoding, not a complete-file witness' : 'manual complete-file carrier')}
write('fixtures.json',fixtures)
record_rows=Dir[A+'/records/*.json'].sort.map{|p|r=JSON.parse(File.read(p));base=p.delete_suffix('.json');%w[stdout stderr].each{|stream|s=File.binread(base+'.'+stream);raise p unless s.bytesize==r[stream]['bytes']&&sha(s)==r[stream]['sha256']};raise p unless r['runner_sha256']==Digest::SHA256.file(A+'/records/capture.rb').hexdigest; {path:p.delete_prefix(A+'/'),exit_code:r['exit_code'],radio:r['revision'],argv:r['argv'],stdout_sha256:r['stdout']['sha256'],stderr_sha256:r['stderr']['sha256']}}
write('records.json',record_rows)
raise 'legacy profile output mismatch' unless File.binread(A+'/records/initial-debug.stdout')==File.binread(A+'/records/legacy-release.stdout')
raise 'primary profile output mismatch' unless File.binread(A+'/records/primary-debug.stdout')==File.binread(A+'/records/primary-release.stdout')
prior='/Users/master/cyber/kadek-bao-anchor/audit/2026-10-12-bao-anchor-research/evidence.tar.gz'
s,err,status=Open3.capture3('tar','-xOf',prior,'./external-inventory.json');raise err unless status.success?
inv=JSON.parse(s)
summary={source_archive:prior,archive_sha256:Digest::SHA256.file(prior).hexdigest,member:'./external-inventory.json',member_sha256:sha(s),registry_revision:inv['registry_revision'],registry_sha256:inv['registry_sha256'],boundary:'Historical exact cached revisions, no fresh network inventory. Full original archive is referenced, not embedded or replayed by this capsule. Nu was subsequently recovered at retained 1e58416ef0501675ef503dd86f80dc1236dfc2a4; Kern absent. Radio a96 and Kadek4d9 support refreshed directly here.',repositories:inv['repositories'].map{|r|{repo:r['repo'],status:r['status'],revision:r['revision'],manifests:(r['manifests']||[]).length}}}
write('historical-inventory-reference.json',summary)
write('measurements.json',{created:Time.now.utc.iso8601,radio:REVS['radio'],initial_git_inputs:initial['git_inputs'].length,support_git_inputs:inputs.length,records:record_rows.length,all_record_exit_codes:record_rows.map{|r|r[:exit_code]},legacy_outputs_equal:true,primary_outputs_equal:true,fixtures:fixtures.length,fixture_bytes:fixtures.sum{|f|f[:bytes]},debug_release_fixtures_equal:true,new_verifier_implemented:false,new_api_work_measured:false,whole_file_synthetic_root_witnessed:false})
FileUtils.cp(__FILE__,A+'/freeze-research.rb')
puts File.read(A+'/measurements.json')
