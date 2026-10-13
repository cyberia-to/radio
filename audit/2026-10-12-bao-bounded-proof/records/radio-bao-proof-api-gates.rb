require '/tmp/radio-bao-proof-final-gates'
# Each label has a fresh private target; no cached rustdoc was present at invocation.
{'default'=>'--default-features','none'=>'--only-explicit-features'}.each do |label,flag|
 args=['/Users/master/.cargo/bin/cargo-semver-checks','semver-checks','-p','cyber-bao','--baseline-rev','v0.1.0',flag]
 r=run('semver-tag-'+label,args,strict:false,extra:['CARGO_NET_OFFLINE=true','RUSTUP_TOOLCHAIN=1.95.0'],target:'/tmp/radio-bao-proof-api-tag-'+label)
 run('parent-semver-tag-'+label,args,kind: :parent,strict:false,extra:['CARGO_NET_OFFLINE=true','RUSTUP_TOOLCHAIN=1.95.0'],target:'/tmp/radio-bao-proof-api-parent-tag-'+label) if r['exit_code']!=0
 run('semver-parent-'+label,['/Users/master/.cargo/bin/cargo-semver-checks','semver-checks','-p','cyber-bao','--baseline-root',PARENT,flag],strict:false,extra:['CARGO_NET_OFFLINE=true','RUSTUP_TOOLCHAIN=1.95.0'],target:'/tmp/radio-bao-proof-api-parent-'+label)
end
