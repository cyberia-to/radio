require '/tmp/radio-bao-proof-final-gates-v2'
# Module ordering changed only. Recheck the new API under both feature boundaries;
# unchanged legacy owner outcomes retain the earlier exact source epoch.
[false,true].each{|release| {'default'=>[],'none'=>['--no-default-features']}.each{|name,flags|
 run("ready-proof-#{release ? 'release' : 'debug'}-#{name}",['cargo','test','--locked','--offline','-p','cyber-bao','--test','proof','--test','proof_failures','--test','proof_allocation',*flags,*(release ? ['--release'] : [])],target:'/tmp/radio-bao-proof-target')
}}
run('ready-clippy-none',['cargo','clippy','--locked','--offline','-p','cyber-bao','--no-default-features','--all-targets','--','-D','warnings'])
[:candidate,:parent].each{|kind|run("ready-format-lib-#{kind}",['/Users/master/.rustup/toolchains/nightly-2025-11-26-aarch64-apple-darwin/bin/rustfmt','--check','--edition','2024','--config','unstable_features=true,skip_children=true','--config','imports_granularity=Crate,group_imports=StdExternalCrate,reorder_imports=true,format_code_in_doc_comments=true','cyber-bao/src/lib.rs'],kind:kind)}
