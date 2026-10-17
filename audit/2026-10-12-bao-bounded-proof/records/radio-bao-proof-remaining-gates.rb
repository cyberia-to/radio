require '/tmp/radio-bao-proof-final-gates-v2'
def paired(name,args,**opts)
 r=run(name,args,**opts)
 run('parent-'+name,args,kind: :parent,**opts) if r['exit_code']!=0
end
paired('owner-clippy-all-final',['cargo','clippy','--locked','--offline','-p','cyber-bao','--all-features','--all-targets','--','-D','warnings'])
{'all'=>['--all-features'],'none'=>['--no-default-features'],'default'=>[]}.each do |name,flags|
 paired('workspace-clippy-'+name,['cargo','clippy','--locked','--offline','--workspace',*flags,'--all-targets','--lib','--bins','--tests','--benches','--examples'])
end
paired('workspace-doctests',['cargo','test','--locked','--offline','--workspace','--all-features','--doc'])
%w[iroh iroh-bench iroh-dns-server iroh-relay].each do |package|
 paired('ci-selector-'+package,['cargo','check','--locked','--offline','-p',package,'--all-features','--lib','--bins'])
end
