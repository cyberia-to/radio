require 'json'
require 'digest'
require 'open3'
require 'time'
root='/tmp/radio-empty-status-code-v1'
rows=JSON.parse(File.read(root+'/index.json'))
body=File.binread(root+'/overview.txt')
def git(repo,rev,path)
 out,err,status=Open3.capture3('git','-C',repo,'show',rev+':'+path)
 raise err unless status.success?
 out.b
end
rows.each_with_index do |r,i|
 data=File.binread(r.fetch('file'))
 raise "input hash #{i}" unless data.bytesize==r['bytes']&&Digest::SHA256.hexdigest(data)==r['sha256']
 exact=if r['revision']
  git(r['repo'],r['revision'],r['path'])
 elsif r['source_revision']
  src=git(r['source_repo'],r['source_revision'],r['source_path'])
  raise 'excerpt parent mismatch' unless Digest::SHA256.hexdigest(src)==r['source_sha256']
  src.lines[(r['line_first']-1)..(r['line_last']-1)].join
 elsif r['original']
  File.binread(r['original'])
 else
  raise "unidentified source #{i}"
 end
 raise "source mismatch #{i}" unless exact==data
 body << "\n===== SOURCE #{i+1}: #{r['owner']} / #{r['path']} =====\nSHA256 #{r['sha256']}; #{r['note']}\n" << data << "\n===== END SOURCE =====\n"
end
raise 'bundle reconstruction mismatch' unless body==File.binread(root+'/brief.txt')
freeze=JSON.parse(File.read('/tmp/radio-empty-status.20261011-60036-oi3wr7/candidate-freeze.json'))
freeze['files'].each do |r|
 %w[/Users/master/cyber/radio-kadek-empty-status /tmp/radio-empty-status.20261011-60036-oi3wr7/candidate/radio].each do |src|
  raise 'source freeze mismatch' unless Digest::SHA256.file(src+'/'+r['path']).hexdigest==r['sha256']
 end
end
info={verified_at:Time.now.utc.iso8601,sections:rows.length,full_git_sources:rows.count{|r|r['revision']},exact_excerpts:rows.count{|r|r['source_revision']},full_candidate_sources:rows.count{|r|r['owner']=='full final candidate source'},sha256:Digest::SHA256.hexdigest(body),index_sha256:Digest::SHA256.file(root+'/index.json').hexdigest,bytes:body.bytesize,candidate_sources_match_both:true}
File.write('/tmp/radio-empty-status-root-code-verification.json',JSON.pretty_generate(info)+"\n")
puts JSON.pretty_generate(info)
