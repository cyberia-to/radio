require '/tmp/radio-bao-proof-final-gates-v2'
[false,true].each do |release|
 {'default'=>[],'none'=>['--no-default-features']}.each do |mode,flags|
 run("complete-proof-#{release ? 'release' : 'debug'}-#{mode}",['cargo','test','--locked','--offline','-p','cyber-bao',*flags,*(release ? ['--release'] : []),'--test','proof','--test','proof_failures','--test','proof_allocation'])
 end
end
run('complete-clippy-none',['cargo','clippy','--locked','--offline','-p','cyber-bao','--no-default-features','--all-targets','--','-D','warnings'])
run('complete-format-new',['/Users/master/.rustup/toolchains/nightly-2025-11-26-aarch64-apple-darwin/bin/rustfmt','--check','--edition','2024','--config','unstable_features=true','--config','imports_granularity=Crate,group_imports=StdExternalCrate,reorder_imports=true,format_code_in_doc_comments=true','cyber-bao/src/proof.rs','cyber-bao/src/proof/output.rs','cyber-bao/tests/proof.rs','cyber-bao/tests/proof_failures.rs','cyber-bao/tests/proof_allocation.rs','cyber-bao/tests/support/proof.rs'])
