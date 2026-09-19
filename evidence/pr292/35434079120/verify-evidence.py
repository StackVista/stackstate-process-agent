import hashlib,json,re,subprocess
from pathlib import Path
root=Path(__file__).resolve().parent
source='c86d936d5833e97b6e6daccb3d1e7beec3e3b2c1'
expected_vex='b30ad305d42a3ddbeeed6526ed2a7ceac96337a071bf044a305d8ee6b4d1f2ac'
expected_exception=subprocess.check_output(['git','show',source+':exceptions/GO-2026-5932.yaml'])
results={}
for arch in ('amd64','arm64'):
 p=root/arch
 provenance=json.loads((p/'provenance.json').read_text())
 assert provenance['source']==source and provenance['arch']==arch
 digest={'amd64':'sha256:e0eeb7d5196e8d1121313aa6e6145c957a6e91687b3a1c045f0a5649b6b5eb65','arm64':'sha256:ff8c855b04a56bf430adbb54de24f0274f5f51cb919cc2fa2ec8d92505172312'}[arch]
 assert provenance['image']=='quay.io/stackstate/stackstate-k8s-process-agent@'+digest
 index=json.loads((p/'published-index.json').read_text())
 assert any(m['digest']==digest and m['platform']['architecture']==arch for m in index['manifests'])
 signature=json.loads((p/'index-signature.json').read_text())
 assert any(x['critical']['image']['docker-manifest-digest']=='sha256:1a45e3280e97fa2e463349d54142b3ca9737d934998b1b1df0c0d93666606ae4' for x in signature)
 expected_binary={'amd64':'1577959a1925498acfe62bf77e0f2344b1b0980ab021923ecbb9d2c6f9a166ed','arm64':'284d8d384a5bedd6e12247ecb2b5ce1d6c9f5a9ddc800a13194091378983ac0b'}[arch]
 assert (p/'binary-sha256.txt').read_text().split()[0]==expected_binary
 subprocess.run(['sha256sum','-c','SHA256SUMS'],cwd=p,check=True,capture_output=True)
 inspect=json.loads((p/'image-inspect.json').read_text())[0]
 assert inspect['Architecture']==arch
 assert inspect['Config']['Labels']['org.opencontainers.image.revision']==source
 modules=(p/'binary-modules.txt').read_text()
 assert 'vcs.revision='+source in modules and 'vcs.modified=false' in modules
 for module,version in [('github.com/containerd/containerd','v1.7.35'),('google.golang.org/grpc','v1.83.2'),('go.opentelemetry.io/otel/sdk','v1.45.0'),('go.opentelemetry.io/otel/exporters/otlp/otlptrace','v1.45.0'),('go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc','v1.45.0')]:
  assert re.search(r'\b'+re.escape(module)+r'\s+'+re.escape(version)+r'\s', modules)
 assert (p/'GO-2026-5932.yaml').read_bytes()==expected_exception
 vexhash=hashlib.sha256((p/'consumed-vex/containerd.openvex.json').read_bytes()).hexdigest()
 assert vexhash==expected_vex
 trivy=json.loads((p/'trivy.json').read_text()); grype=json.loads((p/'grype.json').read_text()); secrets=json.loads((p/'trivy-secrets.json').read_text())
 assert trivy['ArtifactName']==provenance['image'] and secrets['ArtifactName']==provenance['image']
 assert grype['source']['target']['userInput']==provenance['image']
 assert grype['source']['target']['imageID']==inspect['Id']
 tv=[{'id':v['VulnerabilityID'],'package':v['PkgName'],'version':v['InstalledVersion'],'severity':v['Severity']} for r in trivy.get('Results',[]) for v in r.get('Vulnerabilities',[])]
 gv=[{'id':m['vulnerability']['id'],'package':m['artifact']['name'],'version':m['artifact']['version'],'severity':m['vulnerability']['severity']} for m in grype.get('matches',[])]
 assert not any(v['id'] in ('CVE-2026-84445','CVE-2026-53495','CVE-2026-81870') for v in tv+gv)
 assert any(v['id']=='GO-2026-5932' for v in tv)
 ignored=[{'id':m['vulnerability']['id'],'version':m['artifact']['version'],'rules':m.get('appliedIgnoreRules',[])} for m in grype.get('ignoredMatches',[]) if m['artifact']['name']=='github.com/containerd/containerd']
 for cve in ('CVE-2026-50195','CVE-2026-53492','CVE-2026-53489'):
  assert any(m['id']==cve and m['version']=='v1.7.35' and any(r.get('namespace')=='vex' and r.get('vex-status')=='not_affected' for r in m['rules']) for m in ignored)
 secret_count=sum(len(r.get('Secrets',[])) for r in secrets.get('Results',[]))
 assert secret_count==0
 evaluator=(p/'evaluator.txt').read_text()
 assert re.search(r'expired:\s+1',evaluator) and re.search(r'suppressed by exception:\s+0',evaluator)
 sbom=json.loads((p/'inventory.cdx.json').read_text())
 components=sbom['components']; rpm=[c for c in components if c.get('purl','').startswith('pkg:rpm/')]
 assert len(rpm)>0 and len(components)>len(rpm)
 for package,version in [('libpcre2-8-0','10.42-150600.3.3.1'),('glibc','2.38-150600.14.58.1')]:
  assert any(c['name']==package and c['version']==version for c in rpm)
 assert trivy['Metadata']['ImageID']==inspect['Id']
 assert secrets['Metadata']['ImageID']==inspect['Id']
 for name,version in [('github.com/containerd/containerd','v1.7.35'),('google.golang.org/grpc','v1.83.2'),('go.opentelemetry.io/otel/sdk','v1.45.0'),('go.opentelemetry.io/otel/exporters/otlp/otlptrace','v1.45.0'),('go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc','v1.45.0')]:
  assert any(c['name']==name and c['version']==version for c in components)
 assert {v['id'] for v in tv}=={'GO-2026-5932'} and {v['id'] for v in gv}=={'GO-2026-5932'}
 assert re.search(r'unmanaged:\s+0',evaluator)
 assert {v['id'] for v in ignored}=={'CVE-2026-50195','CVE-2026-53492','CVE-2026-53489'}
 results[arch]={'provenance':provenance,'image_id':inspect['Id'],'binary_sha256':(p/'binary-sha256.txt').read_text().split()[0],'vex_sha256':vexhash,'trivy':tv,'grype':gv,'vex_ignored':ignored,'secrets':secret_count,'inventory_components':len(components),'rpm_packages':len(rpm),'evaluator':evaluator}
(root/'verification.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results,indent=2))
