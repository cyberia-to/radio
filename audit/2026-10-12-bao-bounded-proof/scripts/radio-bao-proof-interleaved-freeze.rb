require 'json';require 'digest';require 'fileutils';require 'time'
a='/Users/master/cyber/radio-bao-bounded-proof/audit/2026-10-12-bao-bounded-proof'; dest=a+'/interleaved-oracle'
raise 'exists' if File.exist?(dest); FileUtils.mkdir_p(dest)
Dir['/tmp/kadek-bao-range-literal-v1/*'].each{|p|FileUtils.cp(p,dest)}
FileUtils.cp('/Users/master/cyber/kadek-bao-range-publication/.claude/tasks/bao-range-publication/fixture_oracle.rs',dest+'/fixture_oracle.rs')
rows=Dir[dest+'/*'].sort.map{|p|{path:p.delete_prefix(a+'/'),bytes:File.size(p),sha256:Digest::SHA256.file(p).hexdigest}}
File.write(a+'/interleaved-oracle.json',JSON.pretty_generate({created:Time.now.utc.iso8601,origin:'root independent literal assembler, committed a96 Radio kernels; no encoder/traversal/verifier',files:rows,output_items:6,verification_actions:11,note:'Original manifest output_actions=73 is Kadek adapter copy/planning arithmetic, not Radio iterator item count. This unit asserts 6 output events.'})+"\n")
puts JSON.generate(files:rows.length)
