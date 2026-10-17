require 'json';require 'fileutils';require 'open3';require 'time'
paths=%w[/tmp/radio-bao-proof-target /tmp/radio-bao-proof-clippy-target /tmp/radio-bao-proof-msrv-target /tmp/radio-bao-proof-research-target]
processes=Open3.capture2('ps','-Ao','pid,ppid,etime,args')[0]
raise 'active owned completed cache' if paths.any?{|p|processes.lines.any?{|line|line.include?(p)}}
rows=paths.map{|p|before=File.exist?(p) ? Open3.capture2('du','-sk',p)[0].split.first.to_i : 0;FileUtils.rm_rf(p);{path:p,kib:before,removed:!File.exist?(p)}}
File.write('/Users/master/cyber/radio-bao-bounded-proof/audit/2026-10-12-bao-bounded-proof/completed-owner-cache-cleanup.json',JSON.pretty_generate({at:Time.now.utc.iso8601,scope:'completed private build caches only; raw receipts and frozen source/fixtures retained',paths:rows})+"\n")
puts JSON.generate(rows)
