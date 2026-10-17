require 'json';require 'digest';require 'fileutils';require 'open3';require 'time'
root=Dir.pwd;b=root+'/audit/2026-10-12-bao-bounded-proof';FileUtils.cp('/tmp/radio-bao-proof-final-gates.rb',b+'/records/final-gates.rb')
old=JSON.parse(File.read(b+'/source-freeze.json'))
rows=old['files'].map{|row|p=row['path'];local='source-final/'+p;FileUtils.mkdir_p(File.dirname(b+'/'+local));FileUtils.cp(p,b+'/'+local);{path:p,local:local,bytes:File.size(p),sha256:Digest::SHA256.file(p).hexdigest}}
File.write(b+'/source-final.json',JSON.pretty_generate({parent:`git rev-parse HEAD`.strip,created:Time.now.utc.iso8601,files:rows})+"\n")
config=File.read('.config/nextest.toml')+"\n# Local bounded audit: explicit CI timeout, preserving committed overrides.\n[profile.ci]\nslow-timeout = { period = \"10s\", terminate-after = 3 }\n"
File.write(b+'/nextest.toml',config)
%w[nostd nostd-parent].each do |name|
 dir=b+'/'+name;FileUtils.mkdir_p(dir+'/src');dep=name=='nostd' ? '../../../cyber-bao' : '/tmp/radio-bao-proof-parent-b933/cyber-bao'
 File.write(dir+'/Cargo.toml',"[package]\nname = \"bao-proof-nostd-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[workspace]\n[dependencies]\ncyber-bao = { path = \"#{dep}\", default-features = false }\n[[bin]]\nname = \"link-probe\"\npath = \"src/main.rs\"\n")
 lib=name=='nostd' ? "pub fn job(bytes: &[u8]) -> Result<cyber_bao::proof::ProofVerifier<'_>, cyber_bao::proof::ProofError> { cyber_bao::proof::ProofVerifier::new(bytes, [0; 32], 0, cyber_bao::BlockSize(0), 0..0) }\n" : "pub fn chunk() -> cyber_bao::ChunkNum { cyber_bao::ChunkNum(0) }\n"
 File.write(dir+'/src/lib.rs',"#![no_std]\n"+lib)
 call=name=='nostd' ? 'bao_proof_nostd_probe::job(&[])' : 'bao_proof_nostd_probe::chunk()'
 File.write(dir+'/src/main.rs',"#![no_std]\n#![no_main]\n#[unsafe(no_mangle)]\npub extern \"C\" fn _start() -> ! {\n    let _ = core::hint::black_box(#{call});\n    loop { core::hint::spin_loop(); }\n}\n#[panic_handler]\nfn panic(_: &core::panic::PanicInfo<'_>) -> ! { loop { core::hint::spin_loop(); } }\n")
end
paths=Dir['/Users/master/.rustup/toolchains/{1.95.0,1.89.0,nightly-2025-10-09,nightly-2025-11-26}-aarch64-apple-darwin/bin/{cargo,rustc,rustdoc,rustfmt,cargo-clippy,clippy-driver}']+Dir['/tmp/radio-gate-tools/bin/*']+['/Users/master/.cargo/bin/cargo-semver-checks']
tools=paths.sort.map{|p|{path:p,bytes:File.size(p),sha256:Digest::SHA256.file(p).hexdigest,version:Open3.capture3(p,'--version')[0].strip}}
File.write(b+'/tools.json',JSON.pretty_generate(tools)+"\n")
