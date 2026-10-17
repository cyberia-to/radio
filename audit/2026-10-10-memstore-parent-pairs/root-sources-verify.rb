require 'json'
require 'digest'
require 'open3'
require 'time'
ROOT='/tmp/radio-memstore-pairs.pJDTXk'
def bytes(p) = File.binread(p)
def sha(s) = Digest::SHA256.hexdigest(s)
def git(repo, *args)
  out, err, status = Open3.capture3('git', '-C', repo, *args)
  raise err unless status.success?
  out.b
end
origins=JSON.parse(bytes(ROOT+'/sources.json'))
overlay=JSON.parse(bytes(ROOT+'/source-freeze.json')).to_h { |r| [r['path'],r['sha256']] }
counts={}
export_filters=[]
%w[radio hemera].each do |name|
  repo=name=='radio' ? '/Users/master/cyber/radio-kadek-memstore-pairs' : '/Users/master/cyber/hemera'
  rev=origins[name]
  paths=git(repo,'ls-tree','-r','--name-only',rev).lines.map(&:chomp).reject { |p| p.start_with?('nettools/target/') }
  paths.each do |path|
    original=git(repo,'show',"#{rev}:#{path}")
    if File.symlink?(ROOT+"/parent/#{name}/#{path}")
      mode=git(repo,'ls-tree',rev,'--',path).split.first
      raise 'unexpected symlink' unless mode=='120000'
      %w[parent candidate].each do |scope|
        p=ROOT+"/#{scope}/#{name}/#{path}"
        raise 'symlink export' unless File.symlink?(p) && File.readlink(p).b==original
      end
      next
    end
    if name=='radio' && path=='iroh-ffi/kotlin/gradlew.bat'
      attr=git(repo,'check-attr',"--source=#{rev}",'-a','--',path)
      raise 'unproven CRLF export' unless attr.include?("#{path}: eol: crlf\n") && !original.include?("\r")
      original=original.gsub("\n","\r\n")
      export_filters << {repository:name,path:path,source_attribute:attr,operation:'LF to CRLF'}
    end
    raise "parent #{name}/#{path}" unless bytes(ROOT+"/parent/#{name}/#{path}")==original
    candidate=bytes(ROOT+"/candidate/#{name}/#{path}")
    expected=name=='radio' && overlay.key?(path) ? overlay[path] : sha(original)
    raise "candidate #{name}/#{path}" unless sha(candidate)==expected
  end
  counts[name]=paths.length
  raise 'archive digest' unless sha(bytes(origins['archive_paths'][name]))==origins['archive_sha256'][name]
end
overlay.each do |path,hash|
  %W[#{ROOT}/candidate/radio /Users/master/cyber/radio-kadek-memstore-pairs].each do |root|
    raise "overlay #{path}" unless sha(bytes(root+'/'+path))==hash
  end
end
rows=Dir.glob(ROOT+'/logs/*.json').filter_map do |path|
  row=JSON.parse(bytes(path)); next unless row['argv']
  %w[stdout stderr].each do |stream|
    raise "stream #{path}" unless sha(bytes(path.sub(/json$/,stream)))==row[stream+'_sha256']
  end
  row
end
out={verified_at:Time.now.utc.iso8601,committed_export_paths:counts,explicit_export_filters:export_filters,overlay_paths:overlay.length,gate_records:rows.length,raw_streams:rows.length*2,exit_distribution:rows.group_by { |r| r.fetch('exit') }.transform_values(&:length),source_freeze_sha256:sha(bytes(ROOT+'/source-freeze.json')),byte_exact:true}
File.write('/tmp/kadek-memstore-pairs-root-sources-verification.json',JSON.pretty_generate(out)+"\n")
puts JSON.pretty_generate(out)
