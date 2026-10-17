require 'json';require 'digest';require 'fileutils';require 'time'
ROOT='/Users/master/cyber/radio-bao-bounded-proof'; A=ROOT+'/audit/2026-10-12-bao-bounded-proof'; OLD='/tmp/radio-bao-proof-plan-v1'; OUT='/tmp/radio-bao-proof-code-v1'
raise 'pack exists' if File.exist?(OUT);FileUtils.mkdir_p(OUT)
$sections=[];$context=''.b

def add(label,body,binding)
 body=body.b;n=$sections.length+1;sha=Digest::SHA256.hexdigest(body)
 header="\n===== #{format('%03d',n)} BEGIN #{label} | #{body.bytesize} bytes | SHA256 #{sha} =====\n";footer="\n===== #{format('%03d',n)} END =====\n"
 $context<<header.b;offset=$context.bytesize;$context<<body;$context<<footer.b
 $sections<<{number:n,label:label,offset:offset,bytes:body.bytesize,sha256:sha,header:header,footer:footer,binding:binding}
end
%w[code-brief.md acceptance-map.md gate-report.md review-gates.json comparisons.json source-complete.json interleaved-test-bridge.json test-adjustments.json source-order-bridge.json seals-final-results.json interleaved-oracle.json interleaved-oracle/manifest.json interleaved-oracle/fixture_oracle.rs plan-review/result.md plan-review/invocation.json plan-review/completion.json].each{|p|add('Execution '+p,File.binread(A+'/'+p),{kind:'execution',path:p})}
add('Execution disposition',File.binread(ROOT+'/.claude/tasks/bao-bounded-proof/execution.md'),{kind:'task',path:'.claude/tasks/bao-bounded-proof/execution.md'})
JSON.parse(File.read(A+'/source-complete.json'))['files'].each{|f|add('Candidate full '+f['path'],File.binread(A+'/'+f['local']),{kind:'candidate',path:f['path'],local:f['local']})}
Dir[A+'/seals/src/bin/*.rs'].sort.each{|p|name=p.delete_prefix(A+'/');add('Compiler probe '+name,File.binread(p),{kind:'execution',path:name})}
%w[parent-absence parent-control fixture-freeze].each{|n|%w[json stdout stderr].each{|ext|p='records/'+n+'.'+ext;add('Witness '+p,File.binread(A+'/'+p),{kind:'execution',path:p})}}
old=JSON.parse(File.read(OLD+'/manifest.json'))
selected=[2,3,4,13,14,31,32,33,34,35,36,37,38,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56]+(57..70).to_a
selected.each do |n|
 s=old['sections'].find{|x|x['number']==n};b=s['binding'].dup;b['kind']='research' if b['kind']=='audit'
 add(s['label'],File.binread(OLD+'/'+s['file']),b)
end
raise "oversize #{$context.bytesize}" if $context.bytesize>500000
File.binwrite(OUT+'/context.txt',$context)
File.write(OUT+'/manifest.json',JSON.pretty_generate({created:Time.now.utc.iso8601,revision:'b933829cbe273d2f31fe75ca83125f3ddd8917a2',context_sha256:Digest::SHA256.hexdigest($context),context_bytes:$context.bytesize,sections:$sections})+"\n")
FileUtils.cp(__FILE__,OUT+'/build.rb')
puts JSON.generate(path:OUT,sections:$sections.length,bytes:$context.bytesize,sha256:Digest::SHA256.hexdigest($context))
