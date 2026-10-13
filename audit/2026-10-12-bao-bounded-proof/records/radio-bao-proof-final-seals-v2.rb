require '/tmp/radio-bao-proof-final-gates-v2'
manifest=BASE+'/seals/Cargo.toml'
r=run('seal-control-final',['cargo','run','--locked','--offline','--manifest-path',manifest,'--bin','control'])
raise 'control failed' unless r['exit_code']==0
results=[]
{'fields'=>'E0451','constructor'=>'E0624','conversion'=>'E0277','deserialize'=>'E0277','deserialize_static'=>'E0277','drop_proof'=>'E0505','mutate_proof'=>'E0502','mutate_leaf'=>'E0594'}.each do |bin,code|
 r=run('seal-'+bin+'-final',['cargo','check','--locked','--offline','--manifest-path',manifest,'--bin',bin])
 body=File.read(BASE+'/records/seal-'+bin+'-final.stderr');actual=body.scan(/error\[(E\d+)\]/).flatten.uniq
 raise "unexpected #{bin}: #{actual}" unless r['exit_code']==101&&actual==[code]
 results<<{bin:bin,expected:code,actual:actual,exit_code:r['exit_code']}
end
File.write(BASE+'/seals-final-results.json',JSON.pretty_generate(results)+"\n")
