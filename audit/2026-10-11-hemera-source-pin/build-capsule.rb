require 'json'
require 'digest'
require 'fileutils'
require 'rubygems/package'
require 'zlib'

# Package already frozen evidence. This does not execute Cargo or change source.
root = __dir__
objects = {}
index = []
%w[code-v1 code-v2].each do |name|
  source = '/tmp/radio-hemera-pin-' + name
  pack = JSON.parse(File.read(source + '/pack.json'))
  paths = pack['support'].map { |r| r['path'] } + %w[pack.json review.txt verify.rb verification.json]
  paths.uniq.sort.each do |path|
    full = source + '/' + path
    raise 'unexpected live symlink: ' + full if File.symlink?(full)
    body = File.binread(full)
    digest = Digest::SHA256.hexdigest(body)
    objects[digest] ||= body
    index << { path: name + '/' + path, bytes: body.bytesize, sha256: digest }
  end
end
File.write(root + '/evidence-index.json', JSON.pretty_generate(index) + "\n")
File.open(root + '/evidence.tar.gz', 'wb') do |file|
  Zlib::GzipWriter.wrap(file) do |gzip|
    gzip.mtime = 0
    Gem::Package::TarWriter.new(gzip) do |tar|
      objects.sort.each do |digest, body|
        tar.add_file_simple('objects/' + digest, 0o644, body.bytesize) { |f| f.write(body) }
      end
    end
  end
end
result = {
  logical_files: index.length, unique_objects: objects.length,
  logical_bytes: index.sum { |r| r[:bytes] }, unique_bytes: objects.values.sum(&:bytesize),
  archive_bytes: File.size(root + '/evidence.tar.gz'),
  scope: 'Both frozen CODE packs, complete original and policy PLAN packs and approvals, raw 96 implementation records/192 streams, final and historical source epochs. Large derived rustdoc bodies, redundant original archives and external product trees remain explicitly inventoried omissions, not silently reconstructed evidence.',
  dependencies: 'Portable verifier uses Nushell 0.112.2, tar, mktemp and shasum; no Ruby or Python needed for verification. This Ruby file only records capsule construction.'
}
File.write(root + '/capsule.json', JSON.pretty_generate(result) + "\n")
puts JSON.generate(result)
