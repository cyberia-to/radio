require '/tmp/radio-bao-proof-final-gates-v2'
target=nil
def paired(name,args,**opts)
 r=run(name,args,**opts)
 run('parent-'+name,args,kind: :parent,**opts) if r['exit_code']!=0
end
paired('owner-clippy-all-final',['cargo','clippy','--locked','--offline','-p','cyber-bao','--all-features','--all-targets','--','-D','warnings'],target:nil)
{'all'=>['--all-features'],'none'=>['--no-default-features'],'default'=>[]}.each do |name,flags|
 paired('workspace-clippy-'+name,['cargo','clippy','--locked','--offline','--workspace',*flags,'--all-targets','--lib','--bins','--tests','--benches','--examples'],target:target)
end
paired('workspace-doctests',['cargo','test','--locked','--offline','--workspace','--all-features','--doc'],target:target)
paired('workspace-msrv',['cargo','check','--locked','--offline','--workspace','--all-targets'],toolchain:'1.89.0',target:nil)
paired('workspace-nightly-docs',['cargo','doc','--locked','--offline','--workspace','--all-features','--no-deps','--document-private-items'],toolchain:'nightly-2025-10-09',extra:['RUSTDOCFLAGS=--cfg docsrs'],target:nil)
paired('workspace-format',['cargo','make','format-check'],strict:false,target:target)
paired('workspace-deny',['cargo','deny','--workspace','--all-features','--locked','--offline','check','-Dwarnings'],strict:false,extra:['CARGO_NET_OFFLINE=true'],target:target)
%w[iroh iroh-bench iroh-dns-server iroh-relay].each do |package|
 run('ci-selector-'+package,['cargo','check','--locked','--offline','-p',package,'--all-features','--lib','--bins'],target:target)
end
