require '/tmp/radio-bao-proof-final-gates-v2'
def pair(name,args,**opts)
 r=run(name,args,**opts);run('parent-'+name,args,kind: :parent,**opts) if r['exit_code']!=0
end
pair('workspace-msrv',['cargo','check','--locked','--offline','--workspace','--all-targets'],toolchain:'1.89.0')
pair('workspace-nightly-docs',['cargo','doc','--locked','--offline','--workspace','--all-features','--no-deps','--document-private-items'],toolchain:'nightly-2025-10-09',extra:['RUSTDOCFLAGS=--cfg docsrs'])
pair('workspace-format',['cargo','make','format-check'],strict:false)
pair('workspace-deny',['cargo','deny','--workspace','--all-features','--locked','--offline','check','-Dwarnings'],strict:false,extra:['CARGO_NET_OFFLINE=true'])
