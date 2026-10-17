require 'json'
require 'digest'
require 'fileutils'
require 'open3'
require 'time'
require 'timeout'
ROOT='/Users/master/cyber/radio-bao-bounded-proof'
BASE='ce0fb312faa8770e80efe9afa864106ae6b51552'
HEMERA='d5f0a09539360934fb32db9b2e15a91995607db6'
OUT='/tmp/radio-audit-packaging-pair-v2'
AUDIT='audit/2026-10-13-audit-cargo-packaging'
READER='/Users/master/cyber/kadek-bao-range-publication/audit/2026-10-13-bao-range-research/reader-control'
TC='/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin'
EXTERNAL='/tmp/radio-bao-proof-parent-b933/cyber-bao/Cargo.toml'
raise 'output exists' if File.exist?(OUT)
FileUtils.mkdir_p(OUT)
def sha(s) Digest::SHA256.hexdigest(s) end
def ident(p)
 b=File.binread(p); {path:p,bytes:b.bytesize,sha256:sha(b)}
end
def save(p,v) File.binwrite(p,JSON.pretty_generate(v)+"\n") end
def run(name,argv,env={},cwd:ROOT,ok:true)
 start=Time.now.utc.iso8601(6)
 o,e,s=Open3.capture3(env,*argv,chdir:cwd)
 p=File.join(OUT,name); FileUtils.mkdir_p(File.dirname(p))
 File.binwrite(p+'.stdout',o); File.binwrite(p+'.stderr',e)
 r={started:start,finished:Time.now.utc.iso8601(6),cwd:cwd,argv:argv,env:env,exit_code:s.exitstatus,stdout:ident(p+'.stdout'),stderr:ident(p+'.stderr')}
 save(p+'.json',r)
 raise "#{name} failed: #{s.exitstatus}: #{e}" if ok && !s.success?
 [o,e,r]
end
def git(*args,env:{},input:nil)
 o,e,s=Open3.capture3(env,'git',*args,stdin_data:input||'',chdir:ROOT)
 raise "git failed #{args.inspect}: #{e}" unless s.success?
 o
end
run('source-acquire',['git','clone','--bare','--shared',ROOT,OUT+'/source.git'])
repo=OUT+'/source.git'; url='file://'+repo
renames=JSON.parse(File.read(ROOT+'/'+AUDIT+'/inputs/renames.json'))
entries=['audit/2026-10-09-kadek-slice-traversal/reproduce.nu','audit/2026-10-12-bao-proof-research/verify.nu','audit/2026-10-12-bao-bounded-proof/verify.nu']
allowed=renames.flat_map{|r| [r['logical'],r['archived']]}+entries.flat_map{|p| [p,p.sub(/\.nu$/,'.original.nu.txt')]}
['.claude/tasks/audit-cargo-packaging',AUDIT].each{|d| allowed.concat(Dir.glob(ROOT+'/'+d+'/**/*',File::FNM_DOTMATCH).select{|p|File.file?(p)}.map{|p|p.delete_prefix(ROOT+'/')})}
allowed=allowed.uniq.sort
actual=git('status','--porcelain=v1','--untracked-files=all','-z').split("\0").map{|x|x[3..]}.sort
raise 'unexpected dirty paths' unless actual==allowed
idx={'GIT_INDEX_FILE'=>OUT+'/candidate.index'}
git('--git-dir',repo,'read-tree',BASE,env:idx)
rows=allowed.map do |p|
 f=ROOT+'/'+p
 if File.exist?(f)
  b=File.binread(f); oid=git('--git-dir',repo,'hash-object','-w','--stdin',input:b).strip
  mode=File.executable?(f) ? '100755':'100644'
  git('--git-dir',repo,'update-index','--add','--cacheinfo',mode,oid,p,env:idx)
  {path:p,mode:mode,blob:oid,bytes:b.bytesize,sha256:sha(b)}
 else
  git('--git-dir',repo,'update-index','--index-info',env:idx,input:"0 #{'0'*40}\t#{p}\n")
  {path:p,deleted:true}
 end
end
tree=git('--git-dir',repo,'write-tree',env:idx).strip
who={'GIT_AUTHOR_NAME'=>'Local audit witness','GIT_AUTHOR_EMAIL'=>'audit@localhost','GIT_COMMITTER_NAME'=>'Local audit witness','GIT_COMMITTER_EMAIL'=>'audit@localhost'}
candidate=git('--git-dir',repo,'commit-tree',tree,'-p',BASE,env:who,input:"Local packaging witness only; not an origin release input\n").strip
git('--git-dir',repo,'update-ref','refs/heads/packaging-witness',candidate)
diff=git('--git-dir',repo,'diff-tree','--no-commit-id','--name-only','-r',BASE,candidate).lines.map(&:strip).sort
raise 'complete tree diff differs from explicit allowlist' unless diff==allowed
normal=git('--git-dir',repo,'ls-tree','-r',BASE).lines.reject{|l| p=l.split("\t",2)[1].strip; p.start_with?('audit/','.claude/tasks/')}
normal.each do |line|
 a,p=line.strip.split("\t",2)
 raise "normal source changed #{p}" unless git('--git-dir',repo,'ls-tree',candidate,'--',p).strip==line.strip
end
archived=git('--git-dir',repo,'ls-tree','-r','--name-only',candidate,'audit').lines.map(&:strip).select{|p|File.basename(p)=='Cargo.toml'}
raise "archive manifest escaped #{archived}" unless archived.empty?
save(OUT+'/snapshot.json',{parent:BASE,candidate:candidate,tree:tree,url:url,explicit_paths:rows,changed_paths:diff,unchanged_normal_paths:normal.length,archive_manifest_count:archived.length,scope:'Independent local committed witness; real index and branch untouched.'})
FileUtils.mkdir_p(OUT+'/frozen')
FileUtils.cp(READER+'/reader_probe.rs',OUT+'/frozen/reader_probe.rs')
FileUtils.cp_r(READER+'/literal',OUT+'/frozen/literal')
frozen=Dir.glob(OUT+'/frozen/**/*').select{|p|File.file?(p)}.sort.map{|p|ident(p)}
save(OUT+'/frozen-inputs.json',frozen)
raise 'reader identity mismatch' unless ident(OUT+'/frozen/reader_probe.rs')[:sha256]=='c591a5f63d2a8079ed757fbcdf4a00d9f4b281f2ffe0abff657ebf7731058b15'
run('hemera-acquire',['git','clone','--bare','--shared','/tmp/kadek-bao-reader-cargo-home/git/db/hemera-63696198fb70e01e',OUT+'/hemera.git'])
git('--git-dir',OUT+'/hemera.git','update-ref','refs/heads/pinned',HEMERA)
File.write(OUT+'/gitconfig',"[url \"file://#{OUT}/hemera.git\"]\n\tinsteadOf = https://github.com/cyberia-to/hemera\n")
tools={}; %w[cargo rustc rustdoc].each{|n|tools[n]={identity:ident(TC+'/'+n),version:run('tool-'+n,[TC+'/'+n,'-Vv'])[0]}}
save(OUT+'/tools.json',tools)
external=[]; arms=[]
[['parent',BASE],['candidate',candidate]].each do |label,rev|
 external<<ident(EXTERNAL).merge(point:label+'-before',captured:Time.now.utc.iso8601(6))
 arm=OUT+'/'+label; FileUtils.mkdir_p(arm+'/cargo-home')
 File.write(arm+'/cargo-home/config.toml',"[net]\ngit-fetch-with-cli = true\n[source.crates-io]\nreplace-with = \"cached-registry\"\n[source.cached-registry]\ndirectory = \"/tmp/kadek-bao-anchor-registry\"\n")
 FileUtils.mkdir_p(arm+'/consumer')
 File.write(arm+'/consumer/Cargo.toml',"[package]\nname = \"kadek-bao-reader-control\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n[workspace]\n[[bin]]\nname = \"reader-control\"\npath = \"#{OUT}/frozen/reader_probe.rs\"\n[dependencies]\ncyber-bao = { git = \"#{url}\", rev = \"#{rev}\", default-features = false }\n")
 env={'CARGO_HOME'=>arm+'/cargo-home','CARGO_TARGET_DIR'=>arm+'/target','CARGO_BUILD_JOBS'=>'2','CARGO_INCREMENTAL'=>'0','RUSTC'=>TC+'/rustc','RUSTDOC'=>TC+'/rustdoc','RUSTFLAGS'=>'-Dwarnings','GIT_CONFIG_GLOBAL'=>OUT+'/gitconfig','GIT_CONFIG_NOSYSTEM'=>'1','GIT_ALLOW_PROTOCOL'=>'file','CARGO_HTTP_TIMEOUT'=>'15','CARGO_NET_RETRY'=>'0'}
 cargo=[TC+'/cargo']; manifest=['--manifest-path',arm+'/consumer/Cargo.toml']
 run(label+'/lock',cargo+['generate-lockfile']+manifest,env)
 metadata=JSON.parse(run(label+'/metadata',cargo+['metadata']+manifest+['--locked','--offline','--format-version','1'],env)[0])
 package=metadata['packages'].find{|p|p['name']=='cyber-bao'}
 raise 'wrong selected package/revision' unless package['source']=="git+#{url}?rev=#{rev}##{rev}" && package['manifest_path'].start_with?(arm+'/cargo-home/git/checkouts/') && package['manifest_path'].end_with?('/cyber-bao/Cargo.toml')
 raise 'unexpected dependency closure' unless metadata['packages'].map{|p|p['name']}.sort==%w[cyber-bao cyber-hemera kadek-bao-reader-control]
 raise 'features unexpectedly enabled' unless metadata['resolve']['nodes'].all?{|p|p['features']==[]}
 src=metadata['packages'].reject{|p|p['name']=='kadek-bao-reader-control'}.flat_map do |p|
  r=File.dirname(p['manifest_path']); rev2=p['name']=='cyber-bao' ? BASE : HEMERA
  source_repo=p['name']=='cyber-bao' ? repo : OUT+'/hemera.git'
  prefix=p['name']=='cyber-bao' ? 'cyber-bao/' : 'rs/'
  files=git('--git-dir',source_repo,'ls-tree','-r','--name-only',rev2,'--',prefix).lines.map(&:strip).reject{|x| x.start_with?(prefix+'target/')}
  files.map do |q|
   f=r+'/'+q.delete_prefix(prefix); b=File.binread(f); expected=git('--git-dir',source_repo,'show',rev2+':'+q)
   raise "source bytes mismatch #{q}" unless b==expected.b
   ident(f).merge(package:p['name'],relative:q)
  end
 end
 stable=(src.map{|x|x[:path]}+[arm+'/consumer/Cargo.toml',arm+'/consumer/Cargo.lock',arm+'/cargo-home/config.toml']+frozen.map{|x|x[:path]}+tools.values.map{|x|x[:identity][:path]}).sort
 before=stable.map{|p|ident(p)}; save(arm+'/before.json',before)
 run(label+'/debug',cargo+['run']+manifest+['--locked','--offline','--bin','reader-control','--',OUT+'/frozen/literal'],env)
 run(label+'/release',cargo+['run']+manifest+['--locked','--offline','--release','--bin','reader-control','--',OUT+'/frozen/literal'],env)
 after=stable.map{|p|ident(p)}; save(arm+'/after.json',after); raise 'arm inputs changed' unless before==after
 warnings=%w[lock metadata debug release].to_h{|n|[n,File.read(arm+'/'+n+'.stderr').lines.select{|l|l.start_with?('warning:')} ]}
 if label=='parent'
  raise 'parent did not reproduce duplicate warning' unless warnings.values.all?{|w|w.any?{|l|l.include?('skipping duplicate package')}}
 else
  raise "candidate warnings #{warnings.inspect}" unless warnings.values.flatten.empty?
 end
 save(arm+'/sources.json',src)
 arms<<{label:label,revision:rev,source_count:src.length,stable_inputs:stable.length,warnings:warnings,source_manifest:package['manifest_path']}
 puts "#{label} reader control passed; warnings=#{warnings.values.map(&:length).sum}"; STDOUT.flush
end
external<<ident(EXTERNAL).merge(point:'candidate-after',captured:Time.now.utc.iso8601(6)); save(OUT+'/external-manifest.json',external)
raise 'external warning witness changed' unless external.map{|x|x.values_at(:path,:bytes,:sha256)}.uniq.length==1
stdout=arms.flat_map{|a|%w[debug release].map{|p|File.binread(OUT+'/'+a[:label]+'/'+p+'.stdout')}}
stdout<<File.binread('/tmp/kadek-bao-reader-debug-v1.stdout')
raise 'literal reader result changed' unless stdout.uniq.length==1
source_tuples=arms.map{|a|JSON.parse(File.read(OUT+'/'+a[:label]+'/sources.json')).map{|x|x.values_at('package','relative','bytes','sha256')}}
raise 'production source tuples differ' unless source_tuples.uniq.length==1
save(OUT+'/results.json',{status:'pass',snapshot:candidate,arms:arms,external_stable:true,stdout_sha256:sha(stdout.first),source_tuples_equal:source_tuples.first.length,scope:'Only eight-case consumer commands; metadata normalization checked separately.'})
puts JSON.generate({status:'pass',snapshot:candidate,source_files:source_tuples.first.length,reader_stdout_sha256:sha(stdout.first)})
