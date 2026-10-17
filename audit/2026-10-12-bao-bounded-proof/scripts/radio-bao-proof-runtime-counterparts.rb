require '/tmp/radio-bao-proof-final-gates-v2'
%w[default none].each do |mode|
 source=BASE+'/records/workspace-nextest-'+mode+'-isolated.json'
 sleep 1 until File.exist?(source)
 text=File.read(source.sub(/json$/,'stderr'))
 cases=text.lines.filter_map{|line|m=line.match(/^\s+(?:FAIL|TIMEOUT) \[.*?\] (\S+) (\S+)\s*$/);[m[1],m[2]] if m}.uniq
 raise 'expected runtime red' if cases.empty?
 expression=cases.map{|package,name|"(package(=#{package}) & test(=#{name}))"}.join(' | ')
 args=['cargo','nextest','run','--locked','--offline','--workspace',*(mode=='none' ? ['--no-default-features'] : []),'--lib','--bins','--tests','--config-file',BASE+'/nextest.toml','--profile','ci','--run-ignored','default','--no-fail-fast','--message-format','human','--test-threads','1','-E',expression]
 run('parent-workspace-nextest-'+mode+'-failing-cases',args,kind: :parent)
 File.write(BASE+'/runtime-'+mode+'-comparison.json',JSON.pretty_generate({candidate:'workspace-nextest-'+mode+'-isolated',parent:'parent-workspace-nextest-'+mode+'-failing-cases',scope:'only exact failed cases under same workspace feature/profile/env/config; not a second full parent matrix',cases:cases})+"\n")
end
