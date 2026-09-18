import hashlib,json,re,subprocess
from pathlib import Path
root=Path(__file__).resolve().parent
source='fe7d17e97be17d62ac0ae1cf0760826cc6303f43'
expected_vex='b30ad305d42a3ddbeeed6526ed2a7ceac96337a071bf044a305d8ee6b4d1f2ac'
expected_exception=subprocess.check_output(['git','show',source+':exceptions/GO-2026-5932.yaml'])
results={}
for arch in ('amd64','arm64'):
 p=root/arch
 provenance=json.loads((p/'provenance.json').read_text())
 assert provenance['source']==source and provenance['arch']==arch
 digest={'amd64':'sha256:271e7ac612adc3b89c10aa1bdbc463e4f62d7645c59f3938f27aa2c5500dcc8b','arm64':'sha256:c5deb88549c25db1f42568f7d6bed7f6b5ae1bac1b6785540e97425ef48135de'}[arch]
 assert provenance['image']=='quay.io/stackstate/stackstate-k8s-process-agent@'+digest
 index=json.loads((p/'published-index.json').read_text())
 assert any(m['digest']==digest and m['platform']['architecture']==arch for m in index['manifests'])
 signature=json.loads((p/'index-signature.json').read_text())
 assert any(x['critical']['image']['docker-manifest-digest']=='sha256:6635bd08a5fa43b7f5668a838d9a59042f41eb0603264b465067192bd1b0a112' for x in signature)
 expected_binary={'amd64':'7ef8fb4948f69933c4d0666ac6d0a68a9164635e2405ddd044f700ca786d6b76','arm64':'96b7397a7657873556c2216e3d2fb3daf2fb78f1b24e48e6e8892fd4d14a30d5'}[arch]
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
 for name,version in [('github.com/containerd/containerd','v1.7.35'),('google.golang.org/grpc','v1.83.2'),('go.opentelemetry.io/otel/sdk','v1.45.0'),('go.opentelemetry.io/otel/exporters/otlp/otlptrace','v1.45.0'),('go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc','v1.45.0')]:
  assert any(c['name']==name and c['version']==version for c in components)
 assert {v['id'] for v in tv}=={'GO-2026-5932'} and {v['id'] for v in gv}=={'GO-2026-5932'}
 assert re.search(r'unmanaged:\s+0',evaluator)
 assert {v['id'] for v in ignored}=={'CVE-2026-50195','CVE-2026-53492','CVE-2026-53489'}
 results[arch]={'provenance':provenance,'image_id':inspect['Id'],'binary_sha256':(p/'binary-sha256.txt').read_text().split()[0],'vex_sha256':vexhash,'trivy':tv,'grype':gv,'vex_ignored':ignored,'secrets':secret_count,'inventory_components':len(components),'rpm_packages':len(rpm),'evaluator':evaluator}
(root/'verification.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results,indent=2))
