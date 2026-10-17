require 'json';require 'digest';require 'open3';require 'time'
r='/Users/master/cyber/radio-bao-bounded-proof';a=r+'/audit/2026-10-12-bao-bounded-proof';base='b933829cbe273d2f31fe75ca83125f3ddd8917a2'
def sha(s);Digest::SHA256.hexdigest(s);end
def diagnostics(s)
 s.split(/(?=^error:)/).filter_map do |block|
  next unless block.start_with?('error:')
  next if block.start_with?('error: could not compile')
  loc=block.match(/\s+--> ([^\n]+):(\d+):(\d+)/)
  raise 'unlocated diagnostic' unless loc
  {message:block.lines.first.strip,path:loc[1],line:loc[2].to_i,column:loc[3].to_i,lint:block[/index\.html#([a-z_]+)/,1]}
 end
end
c=diagnostics(File.read(a+'/records/owner-clippy-all-final.stderr'));p=diagnostics(File.read(a+'/records/parent-owner-clippy-all-final.stderr'))
raise 'unexpected counts' unless [c.size,p.size]==[14,11]
raise 'shared diagnostics differ' unless c.first(11)==p
files=c.map{|x|x[:path]}.uniq.map do |path|
 s,err,status=Open3.capture3('git','-C',r,'show',base+':'+path,binmode:true);raise err unless status.success?
 live=File.binread(r+'/'+path);raise 'source changed' unless live==s
 {path:path,bytes:s.bytesize,parent:base,parent_sha256:sha(s),candidate_sha256:sha(live)}
end
extras=c.drop(11).map do |d|
 lines=File.readlines(r+'/'+d[:path]);first=d[:line]-3;last=d[:line]+12
 d.merge(source_excerpt_first:first,source_excerpt_last:last,excerpt:lines[(first-1)..(last-1)].join)
end
pairs=[['ready-format-lib-candidate','ready-format-lib-parent'],['workspace-format','parent-workspace-format']].map do |cn,pn|
 cs=File.binread(a+'/records/'+cn+'.stdout');ps=File.binread(a+'/records/'+pn+'.stdout')
 normalized_c=cs.gsub(r.b,'<REPO>'.b).gsub(%r{(Diff in <REPO>/cyber-bao/src/lib\.rs:)22:},'\\121:')
 normalized_p=ps.gsub('/private/tmp/radio-bao-proof-parent-b933'.b,'<REPO>'.b)
 raise 'normalized formatting differs' unless normalized_c==normalized_p
 {candidate:cn,parent:pn,candidate_bytes:cs.bytesize,parent_bytes:ps.bytesize,candidate_sha256:sha(cs),parent_sha256:sha(ps),normalization:['replace only exact candidate and parent absolute repository roots with <REPO>','candidate lib.rs hunk line22 maps to parent line21 for the one added module declaration'],normalized_equal:true,normalized_sha256:sha(normalized_c),hunks:cs.scan(/^Diff in /).size,stderr_equal:File.binread(a+'/records/'+cn+'.stderr')==File.binread(a+'/records/'+pn+'.stderr')}
end
report={created:Time.now.utc.iso8601,base:base,clippy:{candidate_diagnostics:c,parent_diagnostics:p,first_11_equal:true,extra_candidate_lib_test:extras,source_identities:files,limit:'Final parent command emitted only 11 library diagnostics; the three additional candidate library-test diagnostics are attributed to byte-identical old sources, not claimed to have appeared in that final parent run. No lint-allow rerun or all-feature lint-green claim.'},formatting:pairs}
File.write('/tmp/radio-bao-proof-review-analysis.json',JSON.pretty_generate(report)+"\n")
puts JSON.generate(clippy_candidate:c.length,clippy_parent:p.length,shared:11,extra:extras.map{|e|e.slice(:path,:line,:lint)},unchanged_sources:files.length,formatting:pairs)
