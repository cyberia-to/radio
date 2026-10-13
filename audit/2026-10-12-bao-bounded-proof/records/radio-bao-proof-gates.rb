require 'json'
require 'digest'
require 'fileutils'
$stdout.sync=true
ROOT='/Users/master/cyber/radio-bao-bounded-proof'
BASE=ROOT+'/audit/2026-10-12-bao-bounded-proof'
TC='/Users/master/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin'
ENV95=['env',"PATH=#{TC}:/Users/master/.cargo/bin:/opt/homebrew/bin:/usr/bin:/bin",'CARGO_BUILD_JOBS=2','CARGO_INCREMENTAL=0','RUSTFLAGS=-Dwarnings','RUSTDOCFLAGS=-Dwarnings']
def gate(name,args,dir:ROOT,target:'/tmp/radio-bao-proof-target',env:ENV95)
  base='/tmp/radio-bao-proof-'+name
  Dir.chdir(dir) { system('ruby','/tmp/kadek-root-capture.rb',base,*env,"CARGO_TARGET_DIR=#{target}",*args,out:base+'.runner-output',err:[:child,:out]) }
  r=JSON.parse(File.read(base+'.json'))
  %w[json stdout stderr].each{|s|FileUtils.cp(base+'.'+s,BASE+'/records/'+name+'.'+s)}
  puts "#{name}: exit #{r['exit_code']}"
  r
end
case ARGV.fetch(0)
when 'seals'
  manifest=BASE+'/seals/Cargo.toml'
  r=gate('seal-control-v1',['cargo','run','--locked','--offline','--manifest-path',manifest,'--bin','control'])
  raise 'control failed' unless r['exit_code']==0
  results=[]
  {'fields'=>'E0451','constructor'=>'E0624','conversion'=>'E0277','deserialize'=>'E0277','drop_proof'=>'E0505','mutate_proof'=>'E0502','mutate_leaf'=>'E0594'}.each do |bin,code|
    r=gate('seal-'+bin+'-v1',['cargo','check','--locked','--offline','--manifest-path',manifest,'--bin',bin])
    body=File.read(BASE+'/records/seal-'+bin+'-v1.stderr')
    actual=body.scan(/error\[(E\d+)\]/).flatten.uniq
    raise "unexpected #{bin}:#{actual}" unless r['exit_code']==101 && actual==[code]
    results<<{bin:bin,expected:code,actual:actual,exit_code:r['exit_code']}
  end
  File.write(BASE+'/seals-results.json',JSON.pretty_generate(results)+"\n")
when 'owner'
  gate('owner-clippy-none-v2',['cargo','clippy','--locked','--offline','-p','cyber-bao','--no-default-features','--all-targets','--','-D','warnings'],target:'/tmp/radio-bao-proof-clippy-target')
  [false,true].each do |release|
    {'default'=>[],'none'=>['--no-default-features'],'all'=>['--all-features']}.each do |name,features|
      gate("owner-#{release ? 'release' : 'debug'}-#{name}-v1",['cargo','test','--locked','--offline','-p','cyber-bao',*features,*(release ? ['--release'] : [])])
    end
  end
when 'parent-clippy'
  gate('parent-clippy-all-v1',['cargo','clippy','--locked','--offline','-p','cyber-bao','--all-features','--all-targets','--','-D','warnings'],dir:'/tmp/radio-bao-proof-parent-b933',target:'/tmp/radio-bao-proof-clippy-target')
end
