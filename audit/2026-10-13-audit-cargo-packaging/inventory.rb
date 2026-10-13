require 'json';require 'digest';require 'open3';require 'fileutils';require 'time'
r='/Users/master/cyber/radio-bao-bounded-proof';a=r+'/audit/2026-10-13-audit-cargo-packaging';t=r+'/.claude/tasks/audit-cargo-packaging';base='ce0fb312faa8770e80efe9afa864106ae6b51552'
raise 'task exists' if File.exist?(t);raise 'audit exists' if File.exist?(a)
FileUtils.mkdir_p(t);%w[records original inputs].each{|p|FileUtils.mkdir_p(a+'/'+p)}
cmd=->(*args){o,e,s=Open3.capture3(*args,binmode:true);raise e unless s.success?;o}
raise 'parent drift' unless cmd.call('git','-C',r,'rev-parse','HEAD').strip==base
paths=cmd.call('git','-C',r,'ls-files','-z','audit').split("\0").select{|p|File.basename(p)=='Cargo.toml'}.sort
raise 'seven' unless paths.length==7
scripts=%w[audit/2026-10-09-kadek-slice-traversal/reproduce.nu audit/2026-10-12-bao-proof-research/verify.nu audit/2026-10-12-bao-bounded-proof/verify.nu]
readers=%w[audit/2026-10-12-bao-bounded-proof/code-input/verify.nu audit/2026-10-12-bao-proof-research/files.json audit/2026-10-12-bao-bounded-proof/files.json Cargo.toml cyber-bao/Cargo.toml Cargo.lock]
inputs=(paths+scripts+readers).map do |p|
 data=cmd.call('git','-C',r,'show',base+':'+p);raise 'live drift' unless File.binread(r+'/'+p)==data
 local='original/'+p.sub(/^audit\//,'');local += '.txt' if local.end_with?('Cargo.toml')
 FileUtils.mkdir_p(File.dirname(a+'/'+local));File.binwrite(a+'/'+local,data)
 {repository:'radio',revision:base,path:p,local:local,bytes:data.bytesize,sha256:Digest::SHA256.hexdigest(data)}
end
renames=inputs.select{|x|paths.include?(x[:path])}.map{|x|x.merge(logical:x[:path],archived:x[:path]+'.txt')}
File.write(a+'/inputs/source.json',JSON.pretty_generate(inputs)+"\n")
File.write(a+'/inputs/renames.json',JSON.pretty_generate(renames)+"\n")
old='/Users/master/cyber/kadek-bao-range-publication/audit/2026-10-13-bao-range-research/reader-control'
%w[lock metadata debug release].each{|name|%w[json stdout stderr].each{|ext|FileUtils.cp(old+'/records/'+name+'.'+ext,a+'/records/consumer-ce0-'+name+'.'+ext)}}
FileUtils.cp(old+'/records/capture.rb',a+'/records/capture.rb')
FileUtils.cp(old+'/inputs-before.json',a+'/inputs/consumer-before.json');FileUtils.cp(old+'/inputs-after.json',a+'/inputs/consumer-after.json')
File.write(a+'/inputs/observation.json',JSON.pretty_generate({captured:Time.now.utc.iso8601,base:base,branch:cmd.call('git','-C',r,'branch','--show-current').strip,archived_manifests:paths,repository_AGENTS_present:File.exist?(r+'/AGENTS.md'),repository_CLAUDE_present:File.exist?(r+'/CLAUDE.md'),no_source_edit:true})+"\n")
FileUtils.cp(__FILE__,a+'/inventory.rb')
puts JSON.generate(inputs:inputs.length,manifests:paths.length,manifest_bytes:renames.sum{|x|x[:bytes]},scripts:scripts.length)
