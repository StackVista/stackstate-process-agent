import collections,hashlib,json
from pathlib import Path
b=Path(__file__).resolve().parent
index=json.loads((b/'image-index.json').read_text());desc=json.loads((b/'image-descriptor.json').read_text())
assert 'sha256:'+hashlib.sha256((b/'image-index.json').read_bytes()).hexdigest()==desc['digest']
selection=json.loads((b/'chart-selection.json').read_text())
assert selection['rendered_images']==['quay.io/stackstate/stackstate-k8s-process-agent:00f55972']
package=b/'suse-observability-agent-1.7.8.tgz'
assert package.is_file(), 'Download the published chart archive beside this script before verification.'
assert hashlib.sha256(package.read_bytes()).hexdigest()==selection['package_sha256']
assignment=json.loads((b/'assigned-findings.json').read_text());assert len(assignment)==6
assert all(r['scanners']==['Trivy'] for r in assignment)
commands=json.loads((b/'scan-command-receipts.json').read_text())
assert len(commands)==11 and all(c['exit_code']==0 for c in commands)
reports=[]
for arch in ['amd64','arm64']:
    digest=next(m['digest'] for m in index['manifests'] if m['platform']=={'architecture':arch,'os':'linux'})
    assert 'sha256:'+hashlib.sha256((b/(arch+'-manifest.json')).read_bytes()).hexdigest()==digest
    manifest=json.loads((b/(arch+'-manifest.json')).read_text());image='quay.io/stackstate/stackstate-k8s-process-agent@'+digest
    d=b/arch;t=json.loads((d/'trivy.json').read_text());s=json.loads((d/'trivy-secrets.json').read_text());g=json.loads((d/'grype.json').read_text())
    assert t['ArtifactName']==image and s['ArtifactName']==image
    assert t['Metadata']['ImageID']==manifest['config']['digest']
    assert t['Metadata']['ImageConfig']['architecture']==arch
    assert t['Metadata']['ImageConfig']['config']['Labels']['org.opencontainers.image.revision']=='00f55972777a43e1281461cb5696e9ec09bdef34'
    source=g['source']['target'];assert source['manifestDigest']==digest and source['architecture']==arch and source['imageID']==manifest['config']['digest']
    assert not g['descriptor']['configuration']['vex-documents'] and not g.get('ignoredMatches')
    v=[x for r in t.get('Results',[]) for x in r.get('Vulnerabilities',[])];sec=[x for r in s.get('Results',[]) for x in r.get('Secrets',[])]
    coverage=[]
    pkgs={p['Name']:p.get('Version','')+('-'+p['Release'] if p.get('Release') else '') for r in t['Results'] for p in r.get('Packages',[])}
    for row in assignment:
        assert not any(x['VulnerabilityID']==row['cve'] and x['PkgName']==row['package'] for x in v)
        expected='v1.7.36' if row['package']=='github.com/containerd/containerd' else '2.78.6-150600.4.41.1'
        assert pkgs[row['package']]==expected
        coverage.append({'finding_key':row['finding_key'],'advisory':row['cve'],'package':row['package'],'installed_version':pkgs[row['package']],'reported_by_trivy':False})
    assert not sec
    for typ in ['vuln','secret']:
        c=next(c for c in commands if c['log']==arch+('/trivy.log' if typ=='vuln' else '/trivy-secrets.log'))
        args=c['argv'];assert args[args.index('--vex')+1]=='' and args[args.index('--severity')+1]=='UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL' and args[args.index('--scanners')+1]==typ and args[args.index('--ignorefile')+1]=='/dev/null'
    reports.append({'arch':arch,'image':image,'image_config_digest':manifest['config']['digest'],'source_revision':'00f55972777a43e1281461cb5696e9ec09bdef34','vex_used':False,'assigned_trivy_rows_remaining':0,'assignment_coverage':coverage,'raw_trivy_findings':[{'id':x['VulnerabilityID'],'package':x['PkgName'],'version':x['InstalledVersion'],'severity':x['Severity']} for x in v],'secrets':len(sec),'grype_matches':len(g['matches']),'grype_severity_counts':dict(collections.Counter(x['vulnerability']['severity'] for x in g['matches'])),'grype_ignored_matches':len(g.get('ignoredMatches',[]))})
result={'chart_merge':'8acf7a1596c1e84a2e521a32618e9d95ef609da7','published_chart':selection,'image_index_digest':desc['digest'],'reports':reports,'human_merge_confirmed':True,'normal_internal_chart_publication_confirmed':True,'assigned_six_findings_delivery_criteria_met':True,'raw_all_severity_trivy_zero_findings':False,'residual_unknown':'GO-2026-5932 is outside the six assigned Trivy rows. No VEX applied.','public_chart_release_confirmed':False,'closure_scope':'Complete for the six assigned process-agent findings in the dev/internal chart delivery. This is not an all-estate scan, public/Rancher promotion claim, or zero-all-severity-Trivy claim.','ticket_updated_or_closed':False}
(b/'delivery-verification.json').write_text(json.dumps(result,indent=2)+'\n')
for row in reports:print(row['arch'],'assigned_remaining',row['assigned_trivy_rows_remaining'],'secrets',row['secrets'],'raw_Trivy',row['raw_trivy_findings'],'Grype',row['grype_matches'])
