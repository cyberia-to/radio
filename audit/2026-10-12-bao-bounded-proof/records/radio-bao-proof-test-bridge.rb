require 'json';require 'open3';require 'digest'
b='audit/2026-10-12-bao-bounded-proof';first=JSON.parse(File.read(b+'/tests-first.json'))['files'];ready=JSON.parse(File.read(b+'/source-ready.json'))['files'];diff=''.b;rows=[]
first.each do |f|
 final=ready.find{|r|r['path']==f['path']};a=b+'/'+f['local'];z=b+'/'+final['local'];out,err,status=Open3.capture3('git','diff','--no-index','--',a,z,binmode:true);raise err unless [0,1].include?(status.exitstatus);diff<<out
 rows<<{path:f['path'],first_sha256:f['sha256'],ready_sha256:final['sha256'],unchanged:f['sha256']==final['sha256']}
end
File.binwrite(b+'/test-adjustments.diff',diff)
File.write(b+'/test-adjustments.json',JSON.pretty_generate({rows:rows,diff_sha256:Digest::SHA256.hexdigest(diff),changes:'lexical cancellation/lifetime scope, one scoped reversed-range lint allowance, std/external import grouping; literal expected values unchanged'})+"\n")
