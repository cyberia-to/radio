require 'json';require 'digest';require 'open3';require 'fileutils'
ROOT='/Users/master/cyber/radio-bao-bounded-proof';BASE='ce0fb312faa8770e80efe9afa864106ae6b51552';OUT='/tmp/radio-audit-packaging-staging-tests-v1'
raise 'exists' if File.exist?(OUT);FileUtils.mkdir_p(OUT)
def run(name,*argv)
 o,e,s=Open3.capture3(*argv,binmode:true);File.binwrite(OUT+'/'+name+'.stdout',o);File.binwrite(OUT+'/'+name+'.stderr',e)
 File.write(OUT+'/'+name+'.json',JSON.pretty_generate(argv:argv,exit:s.exitstatus,stdout_sha256:Digest::SHA256.hexdigest(o),stderr_sha256:Digest::SHA256.hexdigest(e))+"\n")
 [o,e,s]
end
def git(*argv)
 o,e,s=Open3.capture3('git','-C',ROOT,*argv,binmode:true);raise e unless s.success?;o
end
def tree
 rows=Dir.glob(ROOT+'/audit/**/*',File::FNM_DOTMATCH).select{|p|File.file?(p)}.sort.map{|p|[p.delete_prefix(ROOT+'/'),File.stat(p).mode&0777,File.size(p),Digest::SHA256.file(p).hexdigest]}
 {files:rows.length,bytes:rows.sum{|x|x[2]},sha256:Digest::SHA256.hexdigest(JSON.generate(rows))}
end
helper=ROOT+'/audit/2026-10-13-audit-cargo-packaging/replay.nu'
specs=[['2026-10-09-kadek-slice-traversal','reproduce.nu',['Cargo.toml']],['2026-10-12-bao-proof-research','verify.nu',['probe/Cargo.toml','primary-probe/Cargo.toml']],['2026-10-12-bao-bounded-proof','verify.nu',['fixture-probe/Cargo.toml','nostd/Cargo.toml','nostd-parent/Cargo.toml','seals/Cargo.toml']]]
stages=[]
specs.each_with_index do |(name,entry,paths),i|
 root=ROOT+'/audit/'+name;code='use '+helper.to_json+' stage; stage '+[root,entry].map(&:to_json).join(' ')+' '+paths.to_json+' | to json'
 o,e,s=run('stage-'+i.to_s,'nu','-c',code);raise e unless s.success?;stage=JSON.parse(o);copy=stage['capsule']
 tracked=git('ls-tree','-r','--name-only',BASE,'--','audit/'+name).lines.map(&:strip)
 actual=Dir.glob(copy+'/**/*',File::FNM_DOTMATCH).select{|p|File.file?(p)}.map{|p|p.delete_prefix(copy+'/')}.sort
 raise 'stage path set mismatch' unless actual==tracked.map{|p|p.delete_prefix('audit/'+name+'/')}.sort
 tracked.each{|p|raise 'staged bytes differ '+p unless File.binread(copy+'/'+p.delete_prefix('audit/'+name+'/'))==git('show',BASE+':'+p)}
 stages<<stage.merge('capsule_name'=>name,'files_equal'=>tracked.length)
 if i==0
  [['db1d62e2cd1e4b2f309fa19bcc158bd29b44753d','parent'],['590e69ea0eebcea4c21320a88eed214dc5459de1','implementation']].each do |rev,arm|
   target=OUT+'/export-'+arm;code='source '+(copy+'/'+entry).to_json+'; prepare-crate '+[ROOT,rev,target,copy].map(&:to_json).join(' ')
   o,e,s=run('prepare-'+arm,'nu','-c',code);raise e unless s.success?
   {'Cargo.toml'=>'Cargo.toml','Cargo.lock'=>'Cargo.lock','src/main.rs'=>'probe.rs'}.each{|p,q|raise 'copy mismatch' unless File.binread(target+'/'+p)==git('show',BASE+':audit/'+name+'/'+q)}
   git('ls-tree','-r','--name-only',rev,'--','cyber-bao').lines.map(&:strip).each do |p|
    expected=git('show',rev+':'+p);expected=expected.sub('path = "../../hemera/rs"','version = "=0.3.1"') if p=='cyber-bao/Cargo.toml';raise 'export mismatch' unless File.binread(target+'/'+p)==expected
   end
  end
 end
 FileUtils.rm_rf(stage['directory'])
end
failures=[]
%w[missing collision].each do |kind|
 base=OUT+'/'+kind;root=base+'/audit/2026-10-12-bao-proof-research';h=base+'/audit/2026-10-13-audit-cargo-packaging';FileUtils.mkdir_p([root+'/probe',root+'/primary-probe',h])
 FileUtils.cp(helper,h+'/replay.nu');FileUtils.cp(ROOT+'/audit/2026-10-12-bao-proof-research/verify.nu',root+'/verify.nu')
 %w[probe primary-probe].each{|p|FileUtils.cp(ROOT+'/audit/2026-10-12-bao-proof-research/'+p+'/Cargo.toml.txt',root+'/'+p+'/Cargo.toml.txt')}
 marker=base+'/historical-ran';File.write(root+'/verify.original.nu.txt','"ran" | save '+marker.to_json+"\nexit 77\n")
 kind=='missing' ? FileUtils.rm(root+'/probe/Cargo.toml.txt') : File.write(root+'/probe/Cargo.toml','collision')
 before=tree;o,e,s=run('failure-'+kind,'nu',root+'/verify.nu','--repo',ROOT,'--siblings','/Users/master/cyber');after=tree
 raise 'failure leaked' if s.success?||File.exist?(marker)||before!=after
 raise 'wrong failure' unless kind=='missing' ? e.include?('Cargo.toml.txt') : e.include?('Logical Cargo path already exists')
 failures<<{case:kind,status:s.exitstatus,before:before,after:after,historical_invoked:false}
end
# Exact wrapper option forwarding measured with a temporary child argument recorder.
cli=[]
specs.each_with_index do |(name,entry,paths),i|
 base=OUT+'/cli-'+i.to_s;root=base+'/audit/'+name;h=base+'/audit/2026-10-13-audit-cargo-packaging';FileUtils.mkdir_p([root,h]);FileUtils.cp(helper,h+'/replay.nu');FileUtils.cp(ROOT+'/audit/'+name+'/'+entry,root+'/'+entry)
 paths.each{|p|FileUtils.mkdir_p(File.dirname(root+'/'+p));FileUtils.cp(ROOT+'/audit/'+name+'/'+p+'.txt',root+'/'+p+'.txt')}
 script=if i==0;'def main [--implementation-revision: string, --radio-repo: path, --hemera-repo: path, --fetch, --full-workspace] { {implementation: $implementation_revision, radio: $radio_repo, hemera: $hemera_repo, fetch: $fetch, full: $full_workspace} | to json }';elsif i==1;'def main [--repo: string, --siblings: string, --live] { {repo: $repo, siblings: $siblings, live: $live} | to json }';else;'def main [--repo: string, --live] { {repo: $repo, live: $live} | to json }';end
 File.write(root+'/'+entry.sub('.nu','.original.nu.txt'),script)
 argv=['nu',root+'/'+entry];argv+=['--implementation-revision','literal-revision','--fetch','--full-workspace'] if i==0
 o,e,s=run('cli-'+i.to_s,*argv);raise e unless s.success?;value=JSON.parse(o)
 expected=i==0 ? {implementation:'literal-revision',radio:File.expand_path('~/cyber/radio'),hemera:File.expand_path('~/cyber/hemera'),fetch:true,full:true} : i==1 ? {repo:base,siblings:OUT,live:false} : {repo:base,live:false}
 raise 'default CLI mismatch' unless value==JSON.parse(JSON.generate(expected))
 cli<<value
end
File.write(OUT+'/results.json',JSON.pretty_generate(stages:stages,failures:failures,default_cli:cli)+"\n")
puts JSON.generate(status:'pass',original_capsules:stages.map{|x|[x['capsule_name'],x['files_equal']]},original_prepare_calls:2,deliberate_failures:failures.length,audit_tree_unchanged:true,default_cli_cases:cli.length)
