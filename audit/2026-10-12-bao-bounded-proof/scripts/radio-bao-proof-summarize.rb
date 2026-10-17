require 'json';require 'digest';require 'time';require 'fileutils'
a='/Users/master/cyber/radio-bao-bounded-proof/audit/2026-10-12-bao-bounded-proof'
rows=Dir[a+'/records/*.json'].sort.map do |p|
 r=JSON.parse(File.read(p));name=File.basename(p,'.json');streams=%w[stdout stderr].map{|s|File.binread(p.sub(/json$/,s)).force_encoding(Encoding::UTF_8)};out=streams.join("\n");lines=out.lines
 tests=out.scan(/test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out/).map{|x|x.map(&:to_i)}
 b=a+'/bindings/'+name+'.json';binding=File.exist?(b) ? JSON.parse(File.read(b)) : nil
 {name:name,revision:r['revision'],exit:r['exit_code'],record:'records/'+name+'.json',record_sha256:Digest::SHA256.file(p).hexdigest,argv:r['argv'],epoch:binding && binding['source_before'],test_aggregate:tests.empty? ? nil : tests.transpose.map(&:sum),nextest_summaries:lines.grep(/Summary \[/).map(&:strip),diagnostics:lines.grep(/^(?:error(?:\[|:)|warning(?:\[|:))/).map(&:strip).uniq,warning_lines:lines.count{|l|l.start_with?('warning:','warning[')},failed_cases:lines.filter_map{|l|m=l.match(/^\s+(FAIL|TIMEOUT) \[.*?\] (\S+) (\S+)\s*$/);m.captures if m}.uniq,stdout:r['stdout'],stderr:r['stderr']}
end
File.write(a+'/gate-ledger.json',JSON.pretty_generate(rows)+"\n")
names=rows.map{|r|r[:name]};pairs=[]
names.grep(/^parent-/).each do |p|
 c=p.delete_prefix('parent-');c=c.sub(/-failing-cases$/,'-isolated')
 next unless names.include?(c)
 pairs << {candidate:c,parent:p,scope:p.end_with?('failing-cases') ? 'exact failing runtime cases only; same workspace features/profile/env; candidate full matrix' : 'same requested command scope on exact current parent; inspect raw diagnostics, scheduling may reveal different subsets'}
end
File.write(a+'/comparisons.json',JSON.pretty_generate(pairs)+"\n")
required=names.grep(/^(?:owner-(?:debug|release)-.*-final|owner-(?:msrv|doc-)|ready-|final-interleaved-|workspace-(?:nextest-.*-isolated|clippy|msrv|nightly|format|deny|doctests)|owner-clippy-all-final|(?:ci-selector|local-native)-|semver-|nostd-(?:library|binary)$)/)
review_names=(required+pairs.select{|p|p[:candidate] && required.include?(p[:candidate])}.map{|p|p[:parent]}).uniq
File.write(a+'/review-gates.json',JSON.pretty_generate(rows.select{|r|review_names.include?(r[:name])})+"\n")
report="# Gate results on exact b933 parent\n\nAll results are local observations, not hosted CI or release acceptance. The full\nargv, source epoch, stream hashes and precise comparison scope are in gate-ledger.json\nand comparisons.json. Raw records remain unchanged. Rustup 1.95 is matched to its\nClippy driver; jobs=2, incremental=0, --locked/--offline are local strengthening.\nNextest uses the retained CI configuration plus an explicit local 10-second slow\nperiod/three-period termination, --test-threads=1 and staging relays. The nightly\ndocumentation row effectively uses RUSTDOCFLAGS=--cfg docsrs; its actual warnings\nare retained, and it is not described as warnings-denied.\n\n| Gate receipt | Exit | Observed result |\n| --- | ---: | --- |\n"
required.each do |n|
 r=rows.find{|x|x[:name]==n};parts=[]
 if r[:nextest_summaries].any?;parts+=r[:nextest_summaries];elsif r[:test_aggregate];parts << "#{r[:test_aggregate][0]} passed / #{r[:test_aggregate][1]} failed / #{r[:test_aggregate][2]} ignored (all Cargo test summaries)";end
 parts << r[:diagnostics].first if r[:exit]!=0 && r[:diagnostics].any?
 parts << "#{r[:warning_lines]} warning lines" if r[:warning_lines]>0
 parts << 'completed successfully' if parts.empty? && r[:exit]==0
 parts << 'see raw output' if parts.empty?
 report << "| `#{n}` | #{r[:exit]} | #{parts.join('; ').gsub('|','\\|')} |\n"
end
report << "\nParent pairs are narrower where named failing-cases; they do not rerun unrelated\npassing tests. Five mDNS cases fail on both default and no-default candidate and\nparent runs. Compilation/lint/docs/fmt/policy reds remain real gate failures even\nwhen present on the exact parent. Unknown causes are not attributed to memory or\nnetwork policy without evidence. Cached offline deny is not a fresh advisory fetch.\n\nThe literal CI selectors iroh/iroh-relay fail because those package names do not\nselect local workspace packages. Explicit cyber-radio/cyber-radio-relay all-feature\nnative checks verify the actual renamed sources. Broad workspace default/none\nruns exercise the local docs/blob/CLI/integration consumers. No external product\nclosure, Linux/Windows run, 32-bit runtime or final no_std allocator-free link is\nclaimed. The isolated thumb library succeeds; candidate and parent binaries fail\nfor the existing Hemera allocator dependency.\n\nSource epochs matter: owner final matrices have 17 new tests (default118, all121,\nnone45); the later one-line module-order correction has targeted ready checks.\nThe final interleaved test adds an 18th new test without production edits, and only\nits focused checks are new. Original source/test/format/Clippy invocation failures,\nthe mixed parent/candidate cache incident and harmless cleanup-guard refusal are\nretained as historical rows; they are not substituted for current final outcomes.\n"
File.write(a+'/gate-report.md',report)
puts JSON.generate(rows:rows.length,pairs:pairs.length,report_bytes:report.bytesize)
