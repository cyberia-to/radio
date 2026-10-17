require 'json'; require 'digest'; require 'fileutils'; require 'open3'; require 'time'
$stdout.sync=true
ROOT='/Users/master/cyber/radio-bao-bounded-proof'; BASE=ROOT+'/audit/2026-10-12-bao-bounded-proof'; PARENT='/tmp/radio-bao-proof-parent-b933'
def epoch(root)
  paths=Dir.chdir(root){Dir.glob('**/*',File::FNM_DOTMATCH).select{|p|File.file?(p)&&!p.start_with?('audit/','.claude/','target/','.git')&&(p.end_with?('.rs','.toml','.lock')||p.start_with?('.github/'))}.sort}
  rows=paths.map{|p|[p,File.size(root+'/'+p),Digest::SHA256.file(root+'/'+p).hexdigest]}
  digest=Digest::SHA256.hexdigest(JSON.generate(rows));FileUtils.mkdir_p(BASE+'/epochs')
  file=BASE+'/epochs/'+digest+'.json';File.write(file,JSON.pretty_generate({root:root,head:Open3.capture2('git','rev-parse','HEAD',chdir:root)[0].strip,files:rows})+"\n") unless File.exist?(file)
  digest
end
def run(name,args,kind: :candidate,toolchain:'1.95.0',extra:[],target:'/tmp/radio-bao-proof-target',strict:true)
  dir=kind==:parent ? PARENT : ROOT; tc='/Users/master/.rustup/toolchains/'+toolchain+'-aarch64-apple-darwin/bin'
  env=['env','-u','RUSTC_WRAPPER',"PATH=#{tc}:/tmp/radio-gate-tools/bin:/Users/master/.cargo/bin:/opt/homebrew/bin:/usr/bin:/bin", "RUSTC=#{tc}/rustc","RUSTDOC=#{tc}/rustdoc",'CARGO_BUILD_JOBS=2','CARGO_INCREMENTAL=0',"CARGO_TARGET_DIR=#{target}",'RUST_BACKTRACE=1','IROH_FORCE_STAGING_RELAYS=1',"RUSTFLAGS=#{strict ? '-Dwarnings' : ''}","RUSTDOCFLAGS=#{strict ? '-Dwarnings' : ''}",*extra]
  base='/tmp/radio-bao-proof-'+name;before=epoch(dir);started=Time.now.utc.iso8601
  puts "start #{name} #{started}"
  Dir.chdir(dir){system('ruby','/tmp/kadek-root-capture.rb',base,*env,*args,out:base+'.runner-output',err:[:child,:out])}
  after=epoch(dir);r=JSON.parse(File.read(base+'.json'))
  %w[json stdout stderr].each{|s|FileUtils.cp(base+'.'+s,BASE+'/records/'+name+'.'+s)}
  FileUtils.mkdir_p(BASE+'/bindings');File.write(BASE+'/bindings/'+name+'.json',JSON.pretty_generate({name:name,kind:kind,source_before:before,source_after:after,record_sha256:Digest::SHA256.file(base+'.json').hexdigest,runner_sha256:Digest::SHA256.file(__FILE__).hexdigest})+"\n")
  puts "finish #{name} exit=#{r['exit_code']}";raise 'source drift' unless before==after;r
end
if ARGV[0]=='final-owner'
  run('owner-clippy-none-final',['cargo','clippy','--locked','--offline','-p','cyber-bao','--no-default-features','--all-targets','--','-D','warnings'],target:'/tmp/radio-bao-proof-clippy-target')
  [false,true].each{|release|{'default'=>[],'none'=>['--no-default-features'],'all'=>['--all-features']}.each{|n,f|run("owner-#{release ? 'release' : 'debug'}-#{n}-final",['cargo','test','--locked','--offline','-p','cyber-bao',*f,*(release ? ['--release'] : [])])}}
  run('format-new-final',['/Users/master/.rustup/toolchains/nightly-2025-11-26-aarch64-apple-darwin/bin/rustfmt','--check','--edition','2024','--config','unstable_features=true','--config','imports_granularity=Crate,group_imports=StdExternalCrate,reorder_imports=true,format_code_in_doc_comments=true','cyber-bao/src/proof.rs','cyber-bao/src/proof/output.rs','cyber-bao/tests/proof.rs','cyber-bao/tests/proof_failures.rs','cyber-bao/tests/proof_allocation.rs','cyber-bao/tests/support/proof.rs'])
end
