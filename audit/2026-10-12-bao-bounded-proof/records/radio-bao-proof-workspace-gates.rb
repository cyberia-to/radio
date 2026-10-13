require '/tmp/radio-bao-proof-final-gates'
target='/tmp/radio-bao-proof-workspace-target'
feature={'all'=>['--all-features'],'default'=>[],'none'=>['--no-default-features']}
feature.each do |name,args|
  r=run('workspace-nextest-'+name,['cargo','nextest','run','--locked','--offline','--workspace',*args,'--lib','--bins','--tests','--config-file',BASE+'/nextest.toml','--profile','ci','--run-ignored','default','--no-fail-fast','--message-format','human','--test-threads','1'],target:target)
  if r['exit_code']!=0 && File.read(BASE+'/records/workspace-nextest-'+name+'.stderr').include?('could not compile')
    run('parent-workspace-nextest-'+name,['cargo','nextest','run','--locked','--offline','--workspace',*args,'--lib','--bins','--tests','--config-file',BASE+'/nextest.toml','--profile','ci','--run-ignored','default','--no-fail-fast','--message-format','human','--test-threads','1'],kind: :parent,target:target)
  end
end
