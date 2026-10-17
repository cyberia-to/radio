require 'json';require 'digest';require 'fileutils';require 'open3';require 'time'
r='/Users/master/cyber/radio-bao-bounded-proof';a=r+'/audit/2026-10-12-bao-bounded-proof'
cache='/tmp/radio-bao-proof-candidate-final-target'
raise 'active candidate cache' if Open3.capture2('ps','-Ao','pid,args')[0].lines.any?{|line|pid=line.split.first.to_i; ![Process.pid,Process.ppid].include?(pid) && line.include?(cache)}
kib=Open3.capture2('du','-sk',cache)[0].split.first.to_i;FileUtils.rm_rf(cache)
File.write(a+'/completed-broad-cache-cleanup.json',JSON.pretty_generate({at:Time.now.utc.iso8601,path:cache,kib:kib,removed:!File.exist?(cache),scope:'completed isolated candidate broad gates; all raw receipts retained; parent cache remains active and untouched'})+"\n")
f=r+'/cyber-bao/tests/proof.rs'
old=JSON.parse(File.read(a+'/source-ready.json'))['files'].find{|x|x['path']=='cyber-bao/tests/proof.rs'}
raise 'source drift' unless Digest::SHA256.file(f).hexdigest==old['sha256']
s=File.binread('/tmp/radio-bao-proof-interleaved-test.txt').sub('assert_eq!(bytes, &body[*f as usize..*f as usize + *n]);','let begin = usize::try_from(*f).unwrap();\n                assert_eq!(bytes, &body[begin..begin + *n]);'.gsub('\\n',"\n")).sub('bytes[start as usize..end as usize]','bytes[usize::try_from(start).unwrap()..usize::try_from(end).unwrap()]')
File.binwrite(a+'/interleaved-test-first.rs',s);File.open(f,'ab'){|io|io.write(s)}
File.write(a+'/interleaved-test-first.json',JSON.pretty_generate({created:Time.now.utc.iso8601,path:'interleaved-test-first.rs',bytes:s.bytesize,sha256:Digest::SHA256.hexdigest(s),production_changed:false,prior_test_sha256:old['sha256']})+"\n")
