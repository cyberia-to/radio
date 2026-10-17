require '/tmp/radio-bao-proof-final-gates-v2'
%w[cyber-radio cyber-radio-relay].each do |package|
 args=['cargo','check','--locked','--offline','-p',package,'--all-features','--lib','--bins']
 r=run('local-native-'+package,args)
 run('parent-local-native-'+package,args,kind: :parent) if r['exit_code']!=0
end
