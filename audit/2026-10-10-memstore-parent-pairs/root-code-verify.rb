require 'json'
require 'digest'
require 'open3'

INDEX = '/tmp/kadek-memstore-pairs-code-index.json'
BUNDLE = '/tmp/kadek-memstore-pairs-code-bundle.txt'
records = JSON.parse(File.binread(INDEX))
bundle = File.binread(BUNDLE)
cursor = 0
git_checks = 0
records.each do |record|
  data = File.binread(record.fetch('input'))
  raise "input hash: #{record['input']}" unless Digest::SHA256.hexdigest(data) == record.fetch('sha256')
  raise "input length: #{record['input']}" unless data.bytesize == record.fetch('bytes')
  if record['revision']
    blob, err, status = Open3.capture3('git', '-C', record.fetch('repository'), 'rev-parse', "#{record.fetch('revision')}:#{record.fetch('path')}")
    raise err unless status.success?
    actual, err, status = Open3.capture3('git', '-C', record.fetch('repository'), 'hash-object', record.fetch('input'))
    raise err unless status.success?
    raise "Git object mismatch: #{record['input']}" unless blob == actual
    git_checks += 1
  end
  next if record.fetch('type') == 'binary_identity_only'
  if record['included_input']
    parts = data.split('[[package]]', -1)
    header = parts.shift
    names = %w[cyber-hemera bytes tokio tokio-macros irpc iroh-io n0-future n0-error range-collections smallvec serde serde_json]
    selected = parts.select { |part| !part.match?(/^source = /) || names.include?(part[/^name = "([^"]+)"$/, 1]) }
    expected = header + selected.map { |part| '[[package]]' + part }.join
    data = File.binread(record.fetch('included_input'))
    raise 'lock selection mismatch' unless data == expected
    raise 'excerpt hash mismatch' unless Digest::SHA256.hexdigest(data) == record.fetch('included_sha256')
  end
  marker = "=== INPUT #{record.fetch('input')} ===\n"
  raise "section marker #{cursor}" unless bundle.byteslice(cursor, marker.bytesize) == marker
  cursor += marker.bytesize
  header_end = bundle.index("\n}\n", cursor)
  raise 'missing header end' unless header_end
  parsed = JSON.parse(bundle.byteslice(cursor, header_end + 2 - cursor))
  raise 'record mismatch' unless parsed == record
  cursor = header_end + 3
  raise "section content: #{record['input']}" unless bundle.byteslice(cursor, data.bytesize) == data
  cursor += data.bytesize
  ending = "\n=== END INPUT ===\n"
  raise 'missing section end' unless bundle.byteslice(cursor, ending.bytesize) == ending
  cursor += ending.bytesize
  cursor += 1 if cursor < bundle.bytesize && bundle.byteslice(cursor, 1) == "\n"
end
raise "unread bytes: #{bundle.bytesize - cursor}" unless cursor == bundle.bytesize
required = %w[iroh-blobs/src/store/fs.rs iroh-blobs/src/store/fs/bao_file.rs iroh-blobs/src/store/fs/options.rs iroh-blobs/src/store/fs/meta.rs iroh-blobs/src/store/fs/entry_state.rs iroh-blobs/src/store/fs/util/entity_manager.rs iroh-blobs/src/api.rs iroh-blobs/src/api/blobs.rs iroh-blobs/src/store/mem.rs iroh-blobs/src/store/util/partial_mem_storage.rs]
required.each { |path| raise "missing full input: #{path}" unless records.any? { |r| r['path'] == path && %w[committed_full_text candidate_complete_text].include?(r['type']) } }
freeze = JSON.parse(File.read('/tmp/radio-memstore-pairs.pJDTXk/source-freeze.json'))
freeze.each do |item|
  row = records.find { |r| r['path'] == item.fetch('path') && r['base_revision'] }
  raise 'candidate manifest mismatch' unless row && row.fetch('sha256') == item.fetch('sha256')
  raise 'candidate base changed' unless row.fetch('base_revision') == '0d11468503c052aa5dcefb0dabc4602bd8efdc60'
  raise 'owned source mismatch' unless Digest::SHA256.file(File.join(row.fetch('repository'), row.fetch('path'))).hexdigest == item.fetch('sha256')
end
receipt_count = 0
Dir['/tmp/radio-memstore-pairs.pJDTXk/logs/*.json'].reject { |p| p.end_with?('.usage.json') }.each do |path|
  record = JSON.parse(File.read(path))
  next unless record['argv']
  %w[stdout stderr].each do |stream|
    raise "raw receipt mismatch: #{path}" unless Digest::SHA256.file(path.sub(/\.json$/, '.' + stream)).hexdigest == record.fetch(stream + '_sha256')
  end
  receipt_count += 1
end
puts JSON.pretty_generate({ records: records.length, git_blob_checks: git_checks, full_text_sections: records.count { |r| r['type'] != 'binary_identity_only' }, bytes: bundle.bytesize, bundle_sha256: Digest::SHA256.hexdigest(bundle), index_sha256: Digest::SHA256.file(INDEX).hexdigest, required_full_import_reopen_sources: required.length, candidate_source_checks: freeze.length, raw_receipt_checks: receipt_count, result: 'verified' })
