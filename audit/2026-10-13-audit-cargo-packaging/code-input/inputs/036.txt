require 'fileutils'; require 'json'; require 'open3'; require 'digest'
base='/tmp/radio-audit-packaging-child-exit-v1'; raise 'exists' if File.exist?(base)
FileUtils.cp_r('/tmp/radio-audit-packaging-staging-tests-v2/cli-2',base)
p=base+'/audit/2026-10-12-bao-bounded-proof'
File.write(p+'/verify.original.nu.txt',"def main [--repo: string, --live] { print --no-newline 'stdout-no-newline'; print --stderr --no-newline 'stderr-no-newline'; exit 77 }\n")
av=['nu',p+'/verify.nu','--repo','/Users/master/cyber/radio-bao-bounded-proof','--live']
o,e,s=Open3.capture3(*av,binmode:true)
File.binwrite(base+'/stdout',o);File.binwrite(base+'/stderr',e)
raise 'stdout altered' unless o=='stdout-no-newline'
raise 'status masked' unless s.exitstatus==77
m=/\Astderr-no-newlineFailed historical replay retained at (\/tmp\/radio-audit-replay\.[^\n]+)\n\z/.match(e); raise e unless m
raise 'failure stage missing' unless File.file?(m[1]+'/capsule/verify.nu')
File.write(base+'/result.json',JSON.pretty_generate(argv:av,status:s.exitstatus,stdout_sha256:Digest::SHA256.hexdigest(o),stderr_sha256:Digest::SHA256.hexdigest(e),retained:m[1],scope:'Exact child streams, status77, retained directory; no added stream newline before explicit helper notice.')+"\n")
puts JSON.generate(status:'pass',child_status:s.exitstatus,retained:m[1])
