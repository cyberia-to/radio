require 'json';require 'digest';require 'fileutils';require 'open3'
r='/Users/master/cyber/radio-bao-bounded-proof';a=r+'/audit/2026-10-13-audit-cargo-packaging';out='/tmp/radio-audit-cargo-packaging-plan-v1';base='ce0fb312faa8770e80efe9afa864106ae6b51552'
raise 'exists' if File.exist?(out);FileUtils.mkdir_p(out+'/inputs')
rows=[];content=''.b
add=->(label,body,binding){i=rows.length+1;sha=Digest::SHA256.hexdigest(body);head="\n===== #{format('%03d',i)} BEGIN #{label} | #{body.bytesize} bytes | SHA256 #{sha} =====\n";tail="\n===== #{format('%03d',i)} END #{label} =====\n";content<<head;offset=content.bytesize;content<<body;content<<tail;local="inputs/#{format('%03d',i)}.txt";File.binwrite(out+'/'+local,body);rows<<{label:label,bytes:body.bytesize,sha256:sha,offset:offset,header:head,footer:tail,local:local,binding:binding}}
cmd=->(*args){s,e,t=Open3.capture3(*args,binmode:true);raise e unless t.success?;s}
%w[research.md plan.md].each{|name|p='.claude/tasks/audit-cargo-packaging/'+name;add.call(p,File.binread(r+'/'+p),{kind:'owned',path:p})}
inputs=JSON.parse(File.read(a+'/inputs/source.json'))
inputs.reject{|f|f['path']=='Cargo.lock'||f['path'].end_with?('/files.json')}.each{|f|add.call(f['path'],File.binread(a+'/'+f['local']),{kind:'git',repository:'radio',revision:base,path:f['path']})}
%w[LICENSE-MIT LICENSE-APACHE].each{|p|add.call(p,cmd.call('git','-C',r,'show',base+':'+p),{kind:'git',repository:'radio',revision:base,path:p})}
inputs.select{|f|f['path'].end_with?('/files.json')}.each do |f|
 original=JSON.parse(File.read(a+'/'+f['local']));selected=original.select{|x|x['path'].end_with?('Cargo.toml')||x['path'].end_with?('verify.nu')}
 body=JSON.pretty_generate(selected)+"\n";add.call(f['path']+' selected logical records',body,{kind:'index',repository:'radio',revision:base,path:f['path'],source_sha256:f['sha256'],source_bytes:f['bytes']})
end
%w[source renames observation consumer-before consumer-after registry].each{|name|p='inputs/'+name+'.json';add.call('Packaging '+p,File.binread(a+'/'+p),{kind:'evidence',path:'audit/2026-10-13-audit-cargo-packaging/'+p})}
reg=JSON.parse(File.read(a+'/inputs/registry.json'));add.call('Registry Radio component',File.binread(a+'/inputs/registry-radio.txt'),reg.merge(kind:'excerpt'))
%w[consumer-ce0-lock consumer-ce0-metadata research-before proof-before].each{|name|%w[json stdout stderr].each{|ext|p='records/'+name+'.'+ext;add.call(p,File.binread(a+'/'+p),{kind:'evidence',path:'audit/2026-10-13-audit-cargo-packaging/'+p})}}
add.call('Capture wrapper',File.binread(a+'/records/capture.rb'),{kind:'evidence',path:'audit/2026-10-13-audit-cargo-packaging/records/capture.rb'})
brief=<<~TEXT
  Fresh PLAN review for a packaging-only defect observed by the committed Kadek reader consumer.
  No existing Radio artifact or production source has changed. Review the proposed seven lossless
  Cargo.toml renames and preservation of the three historical replay scripts via disposable staging.
  Check archive discovery, exact byte/hash preservation, CLI/repo semantics, the temporary Git
  snapshot boundary, finite failure witnesses, and the deliberately scoped consumer verification.
  Existing broad gate reds remain unrefreshed. No version bump, API/spec change or release.

  This readable input includes the full proposed research/plan, every archived Cargo manifest,
  all three original entry scripts, the unchanged proof CODE verifier, both owning manifests,
  both licenses, exact selected historical index rows, current identity inventories, registry
  excerpt, and the full lock/metadata/baseline-replay raw receipts. It omits the full Cargo.lock
  and historical files.json bodies (their exact Git identities are supplied and replayed),
  unrelated production Rust, old full audit bodies/vendor reviews, and duplicated consumer
  debug/release output. Those omitted inputs were not supplied to this reviewer. The retained
  consumer before/after snapshots bind its source and runtime input identities; the package
  fix is not a fresh review of BAO arithmetic or consumer implementation.
TEXT
add.call('Review scope and indexed omissions',brief,{kind:'brief'})
File.binwrite(out+'/context.txt',content)
File.write(out+'/manifest.json',JSON.pretty_generate({parent:base,context_bytes:content.bytesize,context_sha256:Digest::SHA256.hexdigest(content),sections:rows})+"\n")
FileUtils.cp(a+'/inputs/source.json',out+'/source-identities.json')
FileUtils.cp(__FILE__,a+'/plan-pack.rb')
puts JSON.generate(path:out,bytes:content.bytesize,sha256:Digest::SHA256.hexdigest(content),sections:rows.length)
