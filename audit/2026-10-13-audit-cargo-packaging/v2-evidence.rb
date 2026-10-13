require 'json';require 'digest';require 'open3';require 'fileutils'
r='/Users/master/cyber/radio-bao-bounded-proof';a=r+'/audit/2026-10-13-audit-cargo-packaging';base='ce0fb312faa8770e80efe9afa864106ae6b51552';slice='audit/2026-10-09-kadek-slice-traversal'
cmd=->(*v){o,e,s=Open3.capture3(*v,binmode:true);raise e unless s.success?;o}
read=->(p){cmd.call('git','-C',r,'show',base+':'+p)}
inputs=%w[Cargo.lock probe.rs SOURCE-FREEZE.json FIXTURE-SHA256SUMS expected-probe.stdout].map do |p|
 path=slice+'/'+p;b=read.call(path);raise 'live drift' unless File.binread(r+'/'+path)==b
 local='original/2026-10-09-kadek-slice-traversal/'+p;File.binwrite(a+'/'+local,b)
 {repository:'radio',revision:base,path:path,local:local,bytes:b.bytesize,sha256:Digest::SHA256.hexdigest(b)}
end
indices={
 'audit/2026-10-12-bao-proof-research/files.json'=>nil,
 'audit/2026-10-12-bao-proof-research/inputs.json'=>'probe_inputs',
 'audit/2026-10-12-bao-proof-research/primary-inputs.json'=>'files',
 'audit/2026-10-12-bao-bounded-proof/files.json'=>nil,
 'audit/2026-10-12-bao-bounded-proof/seals-first.json'=>nil,
 'audit/2026-10-12-bao-bounded-proof/seals-final-inputs.json'=>nil,
 'audit/2026-10-12-bao-bounded-proof/review/code/files-before-code.json'=>nil,
}
rows=[]
indices.each do |index,field|
 body=read.call(index);table=JSON.parse(body);table=table.fetch(field) if field
 capsule=index.start_with?('audit/2026-10-12-bao-proof-research/') ? 'audit/2026-10-12-bao-proof-research' : 'audit/2026-10-12-bao-bounded-proof'
 table.each_with_index do |row,i|
  next unless row['path']=='verify.nu'||row['path'].end_with?('Cargo.toml')
  next if row['path']=='code-input/verify.nu'
  logical=capsule+'/'+row['path'];precode=index.include?('/review/code/')&&row['path']=='verify.nu'
  archived=if precode;capsule+'/review/code/verify-before-code.nu';elsif row['path']=='verify.nu';capsule+'/verify.original.nu.txt';else;logical+'.txt';end
  old_bytes=read.call(precode ? archived : logical);raise 'index hash mismatch '+index+' '+row['path'] unless old_bytes.bytesize==row['bytes']&&Digest::SHA256.hexdigest(old_bytes)==row['sha256']
  rows<<{index:index,index_sha256:Digest::SHA256.hexdigest(body),pointer:(field ? '/'+field : '')+'/'+i.to_s,logical_path:logical,archived_path:archived,bytes:row['bytes'],sha256:row['sha256'],planned_direct_check:precode ? 'already_historical_variant_before_packaging' : row['path']=='verify.nu' ? 'wrapper_differs_deliberately' : 'logical_path_absent_deliberately'}
 end
end
index='audit/2026-10-12-bao-bounded-proof/plan-input/manifest.json';body=read.call(index)
JSON.parse(body)['sections'].each_with_index do |s,i|
 b=s['binding'];next unless b['kind']=='audit'&&b['path'].end_with?('Cargo.toml')
 logical='audit/2026-10-12-bao-proof-research/'+b['path'];blob=read.call(logical);raise 'context manifest mismatch' unless blob.bytesize==s['bytes']&&Digest::SHA256.hexdigest(blob)==s['sha256']
 rows<<{index:index,index_sha256:Digest::SHA256.hexdigest(body),pointer:'/sections/'+i.to_s,logical_path:logical,archived_path:logical+'.txt',bytes:s['bytes'],sha256:s['sha256'],planned_direct_check:'logical_path_absent_deliberately'}
end
File.write(a+'/inputs/v2-additional-source.json',JSON.pretty_generate(inputs)+"\n")
File.write(a+'/inputs/historical-index-bindings.json',JSON.pretty_generate(rows)+"\n")
exports=[]
[['db1d62e2cd1e4b2f309fa19bcc158bd29b44753d','parent'],['590e69ea0eebcea4c21320a88eed214dc5459de1','implementation']].each do |rev,name|
 dir='/tmp/radio-audit-packaging-prepare-v2/'+name
 {'Cargo.toml'=>'Cargo.toml','Cargo.lock'=>'Cargo.lock','src/main.rs'=>'probe.rs'}.each do |target,source|
  expected=read.call(slice+'/'+source);actual=File.binread(dir+'/'+target);raise 'export mismatch' unless expected==actual
  exports<<{revision:rev,export:name,path:target,source:slice+'/'+source,bytes:actual.bytesize,sha256:Digest::SHA256.hexdigest(actual)}
 end
 paths=cmd.call('git','-C',r,'ls-tree','-r','--name-only',rev,'--','cyber-bao').lines.map(&:strip)
 paths.each do |p|
  expected=cmd.call('git','-C',r,'show',rev+':'+p)
  expected=expected.sub('path = "../../hemera/rs"','version = "=0.3.1"') if p=='cyber-bao/Cargo.toml'
  actual=File.binread(dir+'/'+p);raise 'source export mismatch '+p unless expected==actual
 end
 exports<<{revision:rev,export:name,complete_cyber_bao_files_verified:paths.length,only_existing_manifest_substitution:'path = "../../hemera/rs" => version = "=0.3.1"'}
end
File.write(a+'/inputs/prepare-measurement.json',JSON.pretty_generate({invocation:'/tmp/radio-audit-packaging-original-prepare-v2.json',inputs:inputs.map{|x|x[:path]},exports:exports,cargo_executed:false})+"\n")
FileUtils.cp('/tmp/radio-audit-packaging-prepare-v2/child-code.nu.txt',a+'/inputs/prepare-child-code.nu.txt')
%w[json stdout stderr].each{|p|FileUtils.cp('/tmp/radio-audit-packaging-original-prepare-v2.'+p,a+'/records/original-prepare-v2.'+p)}
FileUtils.cp(__FILE__,a+'/v2-evidence.rb')
puts JSON.generate(index_bindings:rows.length,additional_source_inputs:inputs.length,prepare_exports:exports)
