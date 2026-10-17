require 'json';require 'fileutils';require 'open3';require 'time'
p='/tmp/radio-bao-proof-parent-final-target'
raise 'active parent cache' if Open3.capture2('ps','-Ao','pid,args')[0].lines.any?{|line|pid=line.split.first.to_i; ![Process.pid,Process.ppid].include?(pid) && line.include?(p)}
k=Open3.capture2('du','-sk',p)[0].split.first.to_i;FileUtils.rm_rf(p)
File.write('/Users/master/cyber/radio-bao-bounded-proof/audit/2026-10-12-bao-bounded-proof/completed-parent-cache-cleanup.json',JSON.pretty_generate({at:Time.now.utc.iso8601,path:p,kib:k,removed:!File.exist?(p),scope:'completed isolated parent gates/comparators only; raw outputs and source snapshots retained'})+"\n")
