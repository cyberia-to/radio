require 'json';require 'digest';require 'open3';require 'zlib';require 'fileutils';require 'time'
ROOT='/Users/master/cyber/radio-bao-bounded-root'; OUT=ROOT+'/audit/2026-10-11-hemera-source-pin/hosted'
HEAD='d90a784fa6a7f410492cc6c6d5242527e221c399'; BASE='a11d342594949d4ea542b26366f71d56ef21662d'
def sha(b);Digest::SHA256.hexdigest(b);end
def git(*args);o,e,s=Open3.capture3('git','-C',ROOT,*args);raise e unless s.success?;o;end
def readlog(name);Zlib::GzipReader.open(OUT+'/'+name+'-logs.stdout.gz',&:read).gsub(/\e\[[0-9;]*m/,'').lines.map { |s|s.sub(/^\S+Z /,'').chomp };end
def gzip(path,body);Zlib::GzipWriter.open(path) { |z|z.mtime=0;z.write(body) };end
def identity(path)
 before=git('ls-tree',BASE,'--',path);after=git('ls-tree',HEAD,'--',path)
 {path:path,parent_entry:before.strip,head_entry:after.strip,unchanged:before==after && !before.empty?,parent_present:!before.empty?}
end
# Preserve original root retrieval verbatim; compression changes no raw bytes.
%w[json stderr].each { |ext|FileUtils.cp('/tmp/radio-hemera-pin-hosted-codespell.'+ext,OUT+'/codespell-original.'+ext) }
gzip(OUT+'/codespell-logs.stdout.gz',File.binread('/tmp/radio-hemera-pin-hosted-codespell.stdout'))
FileUtils.cp('/tmp/radio-hemera-pin-fetch-hosted.rb',OUT+'/fetch-hosted.rb')
FileUtils.cp(__FILE__,OUT+'/analyze.rb')
%w[wasm semver fmt docs clippy deny].each do |name|
 m=JSON.parse(Zlib::GzipReader.open(OUT+'/'+name+'-metadata.stdout.gz',&:read))
 raise 'job source changed' unless m['head_sha']==HEAD && m['conclusion']=='failure'
end
all=%w[wasm semver fmt docs clippy deny].to_h { |n|[n,readlog(n)] }
summary=all.map do |name,lines|
 merge=lines.each_cons(2).find { |a,b|a.include?('git log -1 --format=%H') }&.last
 errors=lines.each_with_index.filter_map { |line,i| {line:i+1,text:line} if line.match?(/^(error(?:\[|:)|##\[error\])/)}
 {name:name,checkout_merge:merge,first_error:errors.first,errors:errors,toolchains:lines.select { |s|s.start_with?('rustc ') }.uniq,log_sha256:JSON.parse(File.read(OUT+'/'+name+'-logs.json'))['stdout_sha256']}
end
fmt=all['fmt'].filter_map { |s|m=s.match(%r{\ADiff in /home/runner/work/radio/radio/(.+):(\d+):\z}); m && {path:m[1],line:m[2].to_i} }
fmt_paths=fmt.map { |r|r[:path] }.uniq.sort.map { |p|identity(p) }
raise 'changed fmt input' unless fmt_paths.all? { |r|r[:unchanged] }
spell=readlog('codespell').filter_map do |s|
 m=s.match(%r{\A\./(.+):(\d+): (.+) ==> (.+)\z});next unless m
 path=m[1];line=m[2].to_i;body=git('show',HEAD+':'+path);exact=body.lines.fetch(line-1).chomp
 raise 'spelling word absent' unless exact.include?(m[3])
 identity(path).merge(line:line,word:m[3],suggestion:m[4],source_line:exact,source_sha256:sha(body))
end
introduced=spell.reject { |r|r[:unchanged] };inherited=spell.select { |r|r[:unchanged] }
raise 'unexpected spelling delta' unless spell.length==157 && introduced.length==18 && inherited.length==139 && introduced.all? { |r|!r[:parent_present] && r[:path]=='audit/2026-10-11-hemera-source-pin/evidence-index.json' }
local='/tmp/radio-hemera-pin-code-v2/execution/logs/41-deny-after-policy.stderr'
parent='/tmp/radio-hemera-pin-code-v2/execution/logs/34-deny-parent.stderr'
headings=->(lines) { lines.select { |s|s.start_with?('error[') }.tally }
deny=headings.call(all['deny']);local_head=headings.call(File.read(local).gsub(/\e\[[0-9;]*m/,'').lines.map(&:chomp))
source_paths=%w[.github/workflows/ci.yml Makefile.toml iroh-base/Cargo.toml quinn/Cargo.toml quinn/quinn-udp/Cargo.toml quinn/quinn-udp/build.rs iroh/bench/Cargo.toml]
cfg_entry=->(body) {body.split(/(?=^\[\[package\]\])/).find { |s|s.include?("name = \"cfg_aliases\"\n") }}
lock_base=git('show',BASE+':Cargo.lock');lock_head=git('show',HEAD+':Cargo.lock')
raise 'macro dependency changed' unless cfg_entry.call(lock_base)==cfg_entry.call(lock_head)
data={head:HEAD,parent:BASE,jobs:summary,format:{sections:fmt.length,unique_paths:fmt_paths.length,identities:fmt_paths},codespell:{findings:spell.length,inherited:inherited.length,introduced:introduced.length,records:spell},direct_input_identities:source_paths.map { |p|identity(p) },cfg_aliases_lock_entry:{body:cfg_entry.call(lock_head),sha256:sha(cfg_entry.call(lock_head)),parent_equal:true},deny:{headings:deny,local_after_policy_headings:local_head,headings_equal_to_local_after_policy:deny==local_head},scope:'Hosted head/merge attribution and source identities only. No hosted-parent rerun; architecture/tool versions differ from local gates. Codespell introduction is evidence index data; raw names are preserved, no policy or source edit.'}
gzip(OUT+'/analysis.json.gz',JSON.pretty_generate(data)+"\n")
File.write(OUT+'/summary.json',JSON.pretty_generate(data.reject { |k,v|[:format,:codespell,:deny].include?(k) }.merge(format:{sections:fmt.length,unique_paths:fmt_paths.length,all_paths_unchanged:true},codespell:{findings:157,inherited:139,introduced:18},deny:{headings_equal_to_local_after_policy:deny==local_head,source_denials:deny.select { |k,v|k.start_with?('error[source-not-allowed]') }.values.sum}))+"\n")
puts JSON.generate({format_sections:fmt.length,format_unchanged_paths:fmt_paths.length,codespell:[spell.length,inherited.length,introduced.length],deny_headings_equal:deny==local_head})
