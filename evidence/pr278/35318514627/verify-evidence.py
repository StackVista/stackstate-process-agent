import hashlib,json,re,subprocess
from pathlib import Path
root=Path(__file__).resolve().parent
source='c4840469c675351ab1075f8a8469027828635e51'
expected_vex='b30ad305d42a3ddbeeed6526ed2a7ceac96337a071bf044a305d8ee6b4d1f2ac'
expected_exception=subprocess.check_output(['git','show',source+':exceptions/GO-2026-5932.yaml'])
results={}
for arch in ('amd64','arm64'):
 p=root/arch
 provenance=json.loads((p/'provenance.json').read_text())
 assert provenance['source']==source and provenance['arch']==arch
 inspect=json.loads((p/'image-inspect.json').read_text())[0]
 assert inspect['Architecture']==arch
 assert inspect['Config']['Labels']['org.opencontainers.image.revision']==source
 modules=(p/'binary-modules.txt').read_text()
 assert 'vcs.revision='+source in modules and 'vcs.modified=false' in modules
 for module,version in [('github.com/containerd/containerd','v1.7.35'),('google.golang.org/grpc','v1.83.2'),('go.opentelemetry.io/otel/sdk','v1.44.0')]:
  assert re.search(r'\b'+re.escape(module)+r'\s+'+re.escape(version)+r'\s', modules)
 assert (p/'GO-2026-5932.yaml').read_bytes()==expected_exception
 vexhash=hashlib.sha256((p/'consumed-vex/containerd.openvex.json').read_bytes()).hexdigest()
 assert vexhash==expected_vex
 trivy=json.loads((p/'trivy.json').read_text()); grype=json.loads((p/'grype.json').read_text()); secrets=json.loads((p/'trivy-secrets.json').read_text())
 tv=[{'id':v['VulnerabilityID'],'package':v['PkgName'],'version':v['InstalledVersion'],'severity':v['Severity']} for r in trivy.get('Results',[]) for v in r.get('Vulnerabilities',[])]
 gv=[{'id':m['vulnerability']['id'],'package':m['artifact']['name'],'version':m['artifact']['version'],'severity':m['vulnerability']['severity']} for m in grype.get('matches',[])]
 assert not any(v['id'] in ('CVE-2026-84445','CVE-2026-53495') for v in tv+gv)
 assert any(v['id']=='GO-2026-5932' for v in tv)
 assert any(v['id']=='CVE-2026-81870' for v in tv)
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
 results[arch]={'provenance':provenance,'image_id':inspect['Id'],'binary_sha256':(p/'binary-sha256.txt').read_text().split()[0],'vex_sha256':vexhash,'trivy':tv,'grype':gv,'vex_ignored':ignored,'secrets':secret_count,'inventory_components':len(components),'rpm_packages':len(rpm),'evaluator':evaluator}
(root/'verification.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results,indent=2))
