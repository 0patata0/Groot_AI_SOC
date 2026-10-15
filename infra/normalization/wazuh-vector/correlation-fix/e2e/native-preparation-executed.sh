#!/bin/bash
set -euo pipefail
umask 077
/usr/bin/python3 -B - <<'PYTEST'
import contextlib,datetime,hashlib,io,json,os,pathlib,runpy,shutil,signal,stat,sys,time
R=pathlib.Path('/var/tmp/capstone-correlation-fix-20261014');H=R/'e2e/e2e-stage'
assert os.getuid()==0 and pathlib.Path('/etc/machine-id').read_text().strip()=='1e143067c98a44ffba6eaa925dc038d7'
expected={'e2e-burst.py':'e2704de2da149ed7d3e95972740f6e4a06b61df85eca0018fd54140d86f7d5e5','run-manifest.json':'b76b1003b5dc4733b92f4235c6e7a449152e18bc52d19c83b23ee4551648c0bd'}
for name,sha in expected.items():
 p=H/name;assert not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest()==sha;os.chmod(p,0o600)
for p in [R,H.parent,H]:assert p.is_dir() and not p.is_symlink();os.chmod(p,0o700)
stream=io.StringIO()
with contextlib.redirect_stdout(stream):exec('#!/usr/bin/env python3\n"""Local synthetic aggregate checks. Never imports/runs the operator entry point."""\nimport ast\nimport copy\nimport hashlib\nimport json\nimport pathlib\nimport shutil\nimport subprocess\n\nHERE = pathlib.Path(\'/var/tmp/capstone-correlation-fix-20261014/e2e/e2e-stage\')\nPROJECT = pathlib.Path(\'/var/tmp/capstone-correlation-fix-20261014/canary/canary-candidate\')\nsource = (HERE / "e2e-burst.py").read_text()\ntree = ast.parse(source)\nquery = next(ast.literal_eval(node.value) for node in tree.body\n             if isinstance(node, ast.Assign) and any(\n                 isinstance(target, ast.Name) and target.id == "AGGREGATE_FILTER"\n                 for target in node.targets))\nmanifest = json.loads((HERE / "run-manifest.json").read_text())\nassert manifest["contract"] == "canary-burst-20-v1"\nassert len(manifest["runs"]) == len({r["run_id"] for r in manifest["runs"]}) == 20\nfor run in manifest["runs"]:\n    for scenario, key in [("canary-repeat", "repeat_key"), ("canary-cross", "cross_key")]:\n        assert run[key] == hashlib.sha256((run["run_id"] + ":" + scenario).encode()).hexdigest()\n\nrepeat = [json.loads(x) for x in (PROJECT / "fixtures/correlation/canary-repeat.jsonl").read_text().splitlines()]\ncross = [json.loads(x) for x in (PROJECT / "fixtures/correlation/canary-cross.jsonl").read_text().splitlines()]\nrows = []\nfor number, run in enumerate(manifest["runs"]):\n    for original, rule_id, scenario, key in [\n            (repeat[number % 5], "100293", "canary-repeat", "repeat_key"),\n            (cross[1], "100294", "canary-cross", "cross_key")]:\n        data = copy.deepcopy(original)\n        data["capstone_validation"].update(run_id=run["run_id"], scenario=scenario)\n        data["capstone_norm"]["correlation_key"] = run[key]\n        rows.append({"rule": {"id": rule_id, "level": 3}, "agent": {"id": "001"},\n                     "location": "/var/log/capstone-vector/canary/normalized.jsonl", "data": data})\n\njq = shutil.which("jq")\nassert jq, "preinstalled jq required; do not install a package"\npassed = 1\n\n\ndef check(candidate, expected):\n    global passed\n    result = subprocess.run([jq, "-ce", "-L", str(PROJECT / "history-replay-b"),\n                             "--argjson", "manifest", json.dumps(manifest), query],\n                            input=json.dumps(candidate).encode(), capture_output=True, timeout=10)\n    assert (result.returncode == 0) == expected\n    if expected:\n        tuples = json.loads(result.stdout)\n        assert len(tuples) == 40 and len({(x["run_id"], x["rule_id"]) for x in tuples}) == 40\n    passed += 1\n\n\ncheck(rows, True)\ncheck(list(reversed(rows)), True)\ncheck(rows[:-1], False)\ncheck(rows + [rows[0]], False)\nfor path, value in [\n        (("capstone_validation", "run_id"), manifest["runs"][1]["run_id"]),\n        (("capstone_validation", "scenario"), "canary-historical"),\n        (("capstone_validation", "scenario"), "canary-repeat-duplicate"),\n        (("capstone_norm", "correlation_key"), "f" * 64),\n        (("capstone_norm", "source"), "nftables")]:\n    modified = copy.deepcopy(rows)\n    modified[0]["data"][path[0]][path[1]] = value\n    check(modified, False)\nprint(json.dumps({"kind": "local_synthetic_e2e_aggregate_check", "passed": passed,\n                  "source_ast_valid": True, "synthetic_runs": 20, "expected_tuples": 40,\n                  "remote_connection": False, "operational_input": False,\n                  "driver_runtime_validation": False}))\n',{'__name__':'synthetic_check','__file__':str(H/'test-e2e-contract.py')})
aggregate=json.loads(stream.getvalue());assert aggregate['passed']==10
ns=runpy.run_path(str(H/'e2e-burst.py'));command=ns['command'];safety=ns['b_safety']()
fixture=R/'e2e-timeout-fixture';fixture.mkdir(mode=0o700)
passed=0;orphan_seconds=None;active_remaining=None
try:
 assert command(['/usr/bin/true'],seconds=1)==(0,b'');passed+=1
 for args,seconds in [(['/usr/bin/false'],1),(['/usr/bin/sleep','20'],0.2)]:
  try:command(args,seconds=seconds)
  except RuntimeError as exc:assert str(exc)=='bounded_command_failed';passed+=1
  else:raise AssertionError('expected native failure')
 pidfile=fixture/'child.json'
 childcode="import json,os,pathlib,sys,time; child=os.fork(); os._exit(0) if child else None; p=pathlib.Path('/proc/self/stat'); t=p.read_text(); pathlib.Path(sys.argv[1]).write_text(json.dumps({'pid':os.getpid(),'start':t[t.rfind(')')+2:].split()[19]})); time.sleep(30)"
 started=time.monotonic()
 try:command([sys.executable,'-B','-c',childcode,str(pidfile)],seconds=0.2)
 except RuntimeError as exc:assert str(exc)=='bounded_command_timeout'
 else:raise AssertionError('orphan pipe should require bounded cleanup')
 orphan_seconds=round(time.monotonic()-started,3);assert orphan_seconds<12
 child=json.loads(pidfile.read_text());p=pathlib.Path('/proc',str(child['pid']),'stat')
 active_remaining=0
 if p.exists():
  line=p.read_text();fields=line[line.rfind(')')+2:].split()
  if fields[19]==child['start'] and fields[0] not in ['Z','X']:active_remaining=1
 assert active_remaining==0;passed+=1
finally:
 if (fixture/'child.json').exists():
  child=json.loads((fixture/'child.json').read_text());proc=pathlib.Path('/proc',str(child['pid']),'stat')
  try:
   fd=os.pidfd_open(child['pid'])
   try:
    line=proc.read_text();fields=line[line.rfind(')')+2:].split()
    if fields[19]==child['start'] and fields[0] not in ['Z','X']:signal.pidfd_send_signal(fd,signal.SIGKILL)
   finally:os.close(fd)
  except ProcessLookupError:pass
  except FileNotFoundError:pass
 shutil.rmtree(fixture)
out={'at':datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).isoformat(timespec='seconds'),'kind':'E2E_native_private_preparation','source_sha256':expected,'aggregate_fixture_passed':aggregate['passed'],'timeout_fixture_passed':passed,'orphan_pipe_cleanup_seconds':orphan_seconds,'orphan_active_remaining':active_remaining,'temporary_fixture_removed':not fixture.exists(),'safety':safety,'new_operational_input_rows':0,'new_configuration_changes':0,'driver_main_e2e_executed':False}
p=R/'e2e-native-preparation.json'
with p.open('x') as f:json.dump(out,f,indent=2);f.write('\n')
os.chmod(p,0o600);print(json.dumps(out))
PYTEST
