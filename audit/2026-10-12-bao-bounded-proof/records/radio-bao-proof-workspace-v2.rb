require '/tmp/radio-bao-proof-final-gates-v2'
{'all'=>['--all-features'],'default'=>[],'none'=>['--no-default-features']}.each do |name,args|
  argv=['cargo','nextest','run','--locked','--offline','--workspace',*args,'--lib','--bins','--tests','--config-file',BASE+'/nextest.toml','--profile','ci','--run-ignored','default','--no-fail-fast','--message-format','human','--test-threads','1']
  r=run('workspace-nextest-'+name+'-isolated',argv)
  run('parent-workspace-nextest-'+name+'-isolated',argv,kind: :parent) if r['exit_code']!=0 && File.read(BASE+'/records/workspace-nextest-'+name+'-isolated.stderr').include?('could not compile')
end
