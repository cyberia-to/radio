require 'json';require 'digest'
r='/tmp/radio-audit-packaging-pair-v3'
snapshot=JSON.parse(File.read(r+'/snapshot.json'));normalized=[];reports=[]
%w[parent candidate].each do |arm|
 rev=arm=='parent' ? snapshot['parent'] : snapshot['candidate'];url=snapshot['url'];dir=r+'/'+arm
 data=JSON.parse(File.binread(dir+'/metadata.stdout'));bao=data['packages'].find{|p|p['name']=='cyber-bao'};hemera=data['packages'].find{|p|p['name']=='cyber-hemera'};consumer=data['packages'].find{|p|p['name']=='kadek-bao-reader-control'}
 expect_source="git+#{url}?rev=#{rev}##{rev}";expect_id="git+#{url}?rev=#{rev}#cyber-bao@0.1.0";expect_consumer='path+file://'+dir+'/consumer#kadek-bao-reader-control@0.0.0'
 raise 'source pin mismatch' unless bao['source']==expect_source && bao['id']==expect_id && consumer['id']==expect_consumer
 exact={expect_source=>'RADIO-SOURCE',expect_id=>'RADIO-ID',"git+#{url}?rev=#{rev}"=>'RADIO-DEPENDENCY',expect_consumer=>'CONSUMER-ID'}
 paths={File.dirname(bao['manifest_path'])=>'RADIO-CHECKOUT/cyber-bao',File.dirname(hemera['manifest_path'])=>'HEMERA-CHECKOUT/rs',dir+'/consumer'=>'CONSUMER',dir+'/target'=>'TARGET'}
 raise 'wrong bao checkout' unless paths.keys[0].start_with?(dir+'/cargo-home/git/checkouts/') && paths.keys[0].end_with?('/'+rev[0,7]+'/cyber-bao')
 raise 'wrong hemera checkout' unless paths.keys[1].start_with?(dir+'/cargo-home/git/checkouts/') && paths.keys[1].end_with?('/d5f0a09/rs')
 substitutions=[]
 walk=->(v,pointer,key) do
  case v
  when Hash;v.to_h{|k,x|[k,walk.call(x,pointer+'/'+k,k)]}
  when Array;v.each_with_index.map{|x,i|walk.call(x,pointer+'/'+i.to_s,key)}
  when String
   if exact.key?(v)
    raise 'unexpected ID position' unless %w[id source dependencies pkg workspace_members workspace_default_members root].include?(key)
    z=exact.fetch(v);substitutions<<{pointer:pointer,old:v,new:z,kind:'exact-identifier'};z
   elsif %w[manifest_path src_path target_directory build_directory workspace_root].include?(key)
    matches=paths.select{|old,_|v==old||v.start_with?(old+'/')}
    raise 'ambiguous prefix' if matches.length>1
    if matches.length==1
     old,new=matches.first;z=new+v.delete_prefix(old);substitutions<<{pointer:pointer,old:v,new:z,kind:'validated-path-boundary'};z
    else
     raise 'unexpected unnormalized path' unless key=='src_path' && v==r+'/frozen/reader_probe.rs'
     v
    end
   else;v
   end
  else;v
  end
 end
 norm=walk.call(data,'',nil);normalized<<norm;reports<<{arm:arm,exact_map:exact,path_prefix_map:paths,substitutions:substitutions}
 File.write(r+'/'+arm+'/metadata-normalized.json',JSON.pretty_generate(norm)+"\n")
end
raise 'metadata differs outside explicit allowlist' unless normalized[0]==normalized[1]
File.write(r+'/metadata-comparison.json',JSON.pretty_generate(status:'pass',scope:'Parsed JSON only; exact identifiers and path-boundary substitutions. All other values and array order equal.',arms:reports,normalized_sha256:Digest::SHA256.hexdigest(JSON.generate(normalized[0])))+"\n")
puts JSON.generate(status:'pass',packages:3,resolve_nodes:3,substitutions:reports.map{|x|x[:substitutions].length})
