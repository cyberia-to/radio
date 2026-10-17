require 'json'
require 'digest'
require 'fileutils'
require 'open3'
require 'time'
repo='/Users/master/cyber/radio-bao-bounded-root'
audit=repo+'/audit/2026-10-11-hemera-source-pin'
pack='/tmp/radio-hemera-pin-code-v2'
def sha(path) Digest::SHA256.file(path).hexdigest end
def git(repo,*args)
  out,err,status=Open3.capture3('git','-C',repo,*args)
  raise err unless status.success?
  out
end
freeze=JSON.parse(File.read(pack+'/execution/final/source-freeze.json'))
raise 'parent moved' unless git(repo,'rev-parse','HEAD').strip==freeze['parent']
raise 'index has existing work' unless git(repo,'diff','--cached').empty?
raise 'unexpected tracked delta' unless git(repo,'diff','--name-only').lines.map(&:strip).sort==freeze['files'].map { |r|r['path'] }.sort
freeze['files'].each { |r| raise "source drift #{r['path']}" unless sha(repo+'/'+r['path'])==r['sha256'] }
raw='/tmp/radio-hemera-pin-code-v2-review.txt'
raise 'CODE verdict drift' unless sha(raw)=='1c12426ca43665d7632519c21864721cd703c719f5078887b73ec2e4a7052c46' && File.read(raw).start_with?('APPROVE')
raise 'root portable failed' unless JSON.parse(File.read('/tmp/radio-hemera-pin-root-portable-replay.json'))['exit_code']==0
copies={
  'code-review.txt'=>raw,
  'code-review-invocation.json'=>pack+'/review-invocation.json',
  'code-review-completion.json'=>pack+'/review-completion.json',
  'root-code-verification.json'=>'/tmp/radio-hemera-pin-root-code-v2-verification.json',
  'root-finalize.rb'=>__FILE__,
}
%w[json stdout stderr].each do |suffix|
  copies['root-code-replay.'+suffix]='/tmp/radio-hemera-pin-root-code-v2-replay.'+suffix
  copies['root-portable-replay.'+suffix]='/tmp/radio-hemera-pin-root-portable-replay.'+suffix
end
copies.each { |name,src| dst=audit+'/'+name; raise "exists #{dst}" if File.exist?(dst); FileUtils.cp(src,dst) }
review=<<~'MD'
  # Root disposition

  Accepted for ordinary source merge under the owner's existing review/fix/merge
  instruction. This is a decision/wip change with a major source-identity floor;
  no version bump or release is authorized or claimed by this disposition.

  Input parent: Radio a11d342594949d4ea542b26366f71d56ef21662d; Hemera
  d5f0a09539360934fb32db9b2e15a91995607db6. Approved production patch SHA256:
  90f284eb4083b1312334dc1eb641fe8e73cf074cd676c4ba66396e035cd41042.
  Fresh Grok CODE v2 approved at 2026-10-11T21:37:19Z without blockers.
  [Raw verdict](code-review.txt), [invocation](code-review-invocation.json),
  [completion](code-review-completion.json). Both approved PLANs remain in the
  capsule; the original task files retain their historical pre-review wording.

  Root read every changed production line, both policy/implementation verdicts,
  direct consumer/source contracts and the decisive gate/probe evidence. Independent
  `ruby /tmp/radio-hemera-pin-code-v2/verify.rb` replay verified the current source,
  complete normalized metadata parity and all 96 command records/192 streams;
  [receipt](root-code-replay.json), [result](root-code-verification.json).
  Independent portable `nu --no-config-file .../verify.nu ...` replay also passed;
  [exact command](root-portable-replay.json), [result](root-portable-replay.stdout).
  Neither replay reruns Cargo gates. Current source remained unchanged afterward.

  All reviewer advice is retained: the Cargo rev/lock supplies the exact revision;
  deny's URL entry permits the repository, not a revision. The Hash path/Git split
  sets a major compatibility floor. The soft3 metadata failure is an external
  prerequisite, not a candidate integration test. Fresh docs exit zero with warnings.
  The original two tag exports are input-deviant; only corrected runs use the
  verified tag input. These boundaries are explicit in [the audit](README.md).

  Required broad reds and unexecuted ring/platform obligations stay open. The
  source commit therefore uses wip and quotes the paired all-feature E0599 error;
  the PR carries decision. No allowance or source change suppresses unrelated
  dependency/license/advisory failures. Bounded BAO verification and authenticated
  particle/root association are still subsequent work, so no Kadek phase closes.
MD
File.write(audit+'/review.md',review)
task=repo+'/.claude/tasks/bao-hemera-pin/review.md'
raise 'task disposition exists' if File.exist?(task)
File.write(task,"# Source-pin review disposition\n\nStage: accepted for ordinary source merge. The approved original/amended PLANs\nremain immutable historical artifacts. See [root disposition](../../../audit/2026-10-11-hemera-source-pin/review.md)\nand [execution](execution.md) for evidence, intentional major compatibility floor,\npaired repository reds and open product/release obligations.\n")
readme=audit+'/README.md'
body=File.read(readme)
File.write(readme,body.sub("# Hemera source delivery audit\n","# Hemera source delivery audit\n\n[Final review and root disposition](review.md).\n"))
first_error=File.readlines(pack+'/execution/logs/16-ci-build-all.stderr').find { |line| line.start_with?('error[') }
raise 'first actual error absent' unless first_error&.start_with?('error[E0599]')
File.write('/tmp/radio-hemera-pin-commit.txt',"wip: pin Hemera so Radio resolves without a sibling checkout\n\nRequired all-feature build remains red on parent and candidate:\n#{first_error}\nThe path/Git Hash source split sets a major floor. Exact source, fresh\nPLAN/CODE approvals and retained gate evidence are in the source-pin audit.\nNo version, release pin or tag changes.\n")
paths=Dir.glob(audit+'/**/*').select { |p|File.file?(p) && !File.symlink?(p) && File.basename(p)!='SHA256SUMS' }.sort
File.write(audit+'/SHA256SUMS',paths.map { |p|"#{sha(p)}  #{p.delete_prefix(audit+'/')}\n" }.join)
puts JSON.pretty_generate({finished:Time.now.utc.iso8601,parent:freeze['parent'],production_files:freeze['files'].length,patch_sha256:freeze['patch_sha256'],review:'APPROVE',outer_files:paths.length,outer_sums_sha256:sha(audit+'/SHA256SUMS'),status:'ready for final outer/source validation and explicit staging'})
