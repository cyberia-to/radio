require 'json';require 'digest';require 'open3'
r='/Users/master/cyber/radio-bao-bounded-proof';a=r+'/audit/2026-10-13-audit-cargo-packaging'
raw=Dir.glob(a+'/{records,pair}/**/*.json').sort.filter_map do |p|
 x=JSON.parse(File.read(p)); next unless x.is_a?(Hash)&&x.key?('exit_code')&&x['stdout'].is_a?(Hash)&&x['stdout'].key?('bytes')&&x['stderr'].is_a?(Hash)
 {path:p.delete_prefix(a+'/'),exit_code:x['exit_code']}
end
File.write(a+'/raw-records.json',JSON.pretty_generate(raw)+"\n")
File.write(a+'/final-paths.json','[]') unless File.exist?(a+'/final-paths.json')
File.write(a+'/files.json','[]') unless File.exist?(a+'/files.json')
diff,e,s=Open3.capture3('git','-C',r,'diff','--no-renames','--name-only','ce0fb312faa8770e80efe9afa864106ae6b51552');raise e unless s.success?
unknown,e,s=Open3.capture3('git','-C',r,'ls-files','--others','--exclude-standard');raise e unless s.success?
File.write(a+'/final-paths.json',JSON.pretty_generate((diff.lines+unknown.lines).map(&:strip).uniq.sort)+"\n")
files=Dir.glob(a+'/**/*',File::FNM_DOTMATCH).select{|p|File.file?(p)&&p!=a+'/files.json'}.sort.map{|p|{path:p.delete_prefix(a+'/'),bytes:File.size(p),sha256:Digest::SHA256.file(p).hexdigest}}
File.write(a+'/files.json',JSON.pretty_generate(files)+"\n")
puts JSON.generate(files:files.length,bytes:files.sum{|x|x[:bytes]},raw_records:raw.length)
