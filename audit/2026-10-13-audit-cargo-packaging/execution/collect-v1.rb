require 'json';require 'digest';require 'fileutils';require 'open3'
r='/Users/master/cyber/radio-bao-bounded-proof';a=r+'/audit/2026-10-13-audit-cargo-packaging';pair='/tmp/radio-audit-packaging-pair-v3'
FileUtils.mkdir_p([a+'/execution',a+'/pair',a+'/controls'])
%w[staging-tests-v1 staging-tests-v2 child-exit-v1 pair-v1 pair-v2 pair-v3 metadata-v1].each do |n|
 src='/tmp/radio-audit-packaging-'+n+'.rb';src='/tmp/radio-audit-packaging-staging-tests.rb' if n=='staging-tests-v1'
 FileUtils.cp(src,a+'/execution/'+n+'.rb')
end
names=%w[staging-tests-v1 staging-tests-v2 child-exit-v1 pair-run-v1 pair-run-v2 pair-run-v3 metadata-v1 research-after-v1 research-after-v2 proof-after-v1 proof-after-v2 code-input-after-v1 research-live-after-v1 research-live-after-v2 proof-live-after-v1 proof-live-after-v2]
names.each{|n|%w[json stdout stderr].each{|e|FileUtils.cp('/tmp/radio-audit-packaging-'+n+'.'+e,a+'/records/'+n+'.'+e)}}
%w[v1 v2].each do |v|
 d=a+'/controls/staging-'+v;FileUtils.mkdir_p(d)
 Dir.glob('/tmp/radio-audit-packaging-staging-tests-'+v+'/*').select{|p|File.file?(p)&&%w[.json .stdout .stderr].include?(File.extname(p))}.each{|p|FileUtils.cp(p,d)}
end
FileUtils.mkdir_p(a+'/controls/child-exit-v1'); %w[stdout stderr result.json].each{|p|FileUtils.cp('/tmp/radio-audit-packaging-child-exit-v1/'+p,a+'/controls/child-exit-v1/'+p)}
%w[snapshot.json external-manifest.json frozen-inputs.json tools.json results.json metadata-comparison.json gitconfig].each{|p|FileUtils.cp(pair+'/'+p,a+'/pair/'+p)}
%w[source-acquire hemera-acquire tool-cargo tool-rustc tool-rustdoc].each{|n|%w[json stdout stderr].each{|e|FileUtils.cp(pair+'/'+n+'.'+e,a+'/pair/'+n+'.'+e)}}
%w[parent candidate].each do |arm|
 d=a+'/pair/'+arm;FileUtils.mkdir_p(d)
 %w[lock metadata debug release].each{|n|%w[json stdout stderr].each{|e|FileUtils.cp(pair+'/'+arm+'/'+n+'.'+e,d+'/'+n+'.'+e)}}
 %w[before.json after.json sources.json metadata-normalized.json].each{|p|FileUtils.cp(pair+'/'+arm+'/'+p,d+'/'+p)}
 FileUtils.cp(pair+'/'+arm+'/consumer/Cargo.toml',d+'/consumer.Cargo.toml.txt');FileUtils.cp(pair+'/'+arm+'/consumer/Cargo.lock',d+'/consumer.Cargo.lock.txt');FileUtils.cp(pair+'/'+arm+'/cargo-home/config.toml',d+'/cargo-config.toml.txt')
end
FileUtils.cp_r(pair+'/frozen',a+'/pair/frozen')
FileUtils.cp('/tmp/radio-bao-proof-parent-b933/cyber-bao/Cargo.toml',a+'/pair/external.Cargo.toml.txt')
o,e,s=Open3.capture3('git','--git-dir',pair+'/source.git','bundle','create',a+'/pair/candidate.bundle','refs/heads/packaging-witness','^ce0fb312faa8770e80efe9afa864106ae6b51552',binmode:true);raise e unless s.success?
File.write(a+'/pair/bundle-command.json',JSON.pretty_generate(argv:['git','--git-dir',pair+'/source.git','bundle','create',a+'/pair/candidate.bundle','refs/heads/packaging-witness','^ce0fb312faa8770e80efe9afa864106ae6b51552'],exit:0,stdout:o,stderr:e)+"\n")
# Bind exact final packaging code independently of subsequent audit/report additions.
paths=JSON.parse(File.read(a+'/inputs/renames.json')).map{|x|x['archived']}+%w[audit/2026-10-09-kadek-slice-traversal/reproduce.nu audit/2026-10-09-kadek-slice-traversal/reproduce.original.nu.txt audit/2026-10-12-bao-proof-research/verify.nu audit/2026-10-12-bao-proof-research/verify.original.nu.txt audit/2026-10-12-bao-bounded-proof/verify.nu audit/2026-10-12-bao-bounded-proof/verify.original.nu.txt audit/2026-10-13-audit-cargo-packaging/replay.nu]
File.write(a+'/execution/source-freeze.json',JSON.pretty_generate(paths.map{|p|{path:p,bytes:File.size(r+'/'+p),sha256:Digest::SHA256.file(r+'/'+p).hexdigest}})+"\n")
puts JSON.generate(archived_inputs:7,frozen_packaging_files:paths.length,pair_bundle_bytes:File.size(a+'/pair/candidate.bundle'))
