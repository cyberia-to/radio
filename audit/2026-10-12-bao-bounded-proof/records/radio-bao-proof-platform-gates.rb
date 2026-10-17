require '/tmp/radio-bao-proof-final-gates'
run('owner-doc-default',['cargo','doc','--locked','--offline','-p','cyber-bao','--no-deps'])
run('owner-doc-none',['cargo','doc','--locked','--offline','-p','cyber-bao','--no-default-features','--no-deps'])
%w[nostd nostd-parent].each do |n|
  manifest=BASE+'/'+n+'/Cargo.toml'
  run(n+'-lock',['cargo','generate-lockfile','--offline','--manifest-path',manifest])
  run(n+'-library',['cargo','check','--locked','--offline','--manifest-path',manifest,'--lib','--target','thumbv7em-none-eabi'])
  run(n+'-binary',['cargo','build','--locked','--offline','--manifest-path',manifest,'--bin','link-probe','--target','thumbv7em-none-eabi'])
end
run('owner-msrv',['cargo','check','--locked','--offline','-p','cyber-bao','--no-default-features','--lib'],toolchain:'1.89.0',target:'/tmp/radio-bao-proof-msrv-target')
run('parent-owner-msrv',['cargo','check','--locked','--offline','-p','cyber-bao','--no-default-features','--lib'],kind: :parent,toolchain:'1.89.0',target:'/tmp/radio-bao-proof-msrv-target')
