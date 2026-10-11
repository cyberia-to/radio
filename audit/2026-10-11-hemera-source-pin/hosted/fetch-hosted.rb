require 'json'; require 'digest'; require 'open3'; require 'fileutils'; require 'time'; require 'zlib'
root='/Users/master/cyber/radio-bao-bounded-root/audit/2026-10-11-hemera-source-pin/hosted'
FileUtils.mkdir_p(root)
name,id=ARGV
raise 'bad label' unless name.match?(/\A[a-z]+\z/) && id.match?(/\A[0-9]+\z/)
%w[metadata logs].each do |kind|
  endpoint='repos/cyberia-to/radio/actions/jobs/'+id+(kind=='logs' ? '/logs' : '')
  argv=['gh','api',endpoint]
  started=Time.now.utc.iso8601
  out,err,status=Open3.capture3(*argv)
  finished=Time.now.utc.iso8601
  base=root+'/'+name+'-'+kind
  raise 'already retrieved: '+base if File.exist?(base+'.json')
  Zlib::GzipWriter.open(base+'.stdout.gz') { |z|z.mtime=0;z.write(out) }
  File.binwrite(base+'.stderr',err)
  row={job_id:id.to_i,label:name,kind:kind,argv:argv,cwd:Dir.pwd,started:started,finished:finished,exit:status.exitstatus,signal:status.termsig,stdout_bytes:out.bytesize,stdout_sha256:Digest::SHA256.hexdigest(out),stdout_gzip_sha256:Digest::SHA256.file(base+'.stdout.gz').hexdigest,stderr_bytes:err.bytesize,stderr_sha256:Digest::SHA256.hexdigest(err),hosted_head:'d90a784fa6a7f410492cc6c6d5242527e221c399'}
  File.write(base+'.json',JSON.pretty_generate(row)+"\n")
  puts JSON.generate(row.reject{|k,v|%i[argv cwd].include?(k)})
end
