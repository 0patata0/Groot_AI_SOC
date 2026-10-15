#!/bin/bash
# Isolated native Bash fixture; full translated scripts, no production paths used.
set -euo pipefail
umask 077
source_root=${1:?source root containing infra/hermes required}
fixture=$(mktemp -d "${TMPDIR:-/tmp}/capstone-hermes-legacy-gate.XXXXXX")
cleanup(){ rm -rf -- "$fixture"; }
trap cleanup EXIT
python3 - "$source_root" "$fixture" <<'PY'
import hashlib, pathlib, sys
source, fixture = map(pathlib.Path, sys.argv[1:])
begin = '# BEGIN managed-prestart legacy gate\n'
end = '# END managed-prestart legacy gate\n'
message = 'Legacy Hermes deployment blocked: managed guard state exists. Review the fixed root prestart path infra/automation/ansible/hermes-prestart-local-b.sh.'
gateway = begin + """if [[ -e /etc/capstone-hermes-guard || -L /etc/capstone-hermes-guard ||
      -e /var/lib/capstone-automation/hermes-guard || -L /var/lib/capstone-automation/hermes-guard ]]; then
  printf '%s\\n' 'MESSAGE' >&2
  exit 78
fi
""".replace('MESSAGE', message) + end
deploy = begin + """case "${1:-}" in
  prep|test|all)
    if [[ -e /etc/capstone-hermes-guard || -L /etc/capstone-hermes-guard ||
          -e /var/lib/capstone-automation/hermes-guard || -L /var/lib/capstone-automation/hermes-guard ]]; then
      printf '%s\\n' 'MESSAGE' >&2
      exit 78
    fi
    ;;
esac
""".replace('MESSAGE', message) + end
specs = [
    ('deploy_gateway_B.sh', gateway, '56bf745b0cbd11c41dfa75c98d1927236384b6d24e3d9701eeca6054c43ce232'),
    ('deploy_hermes_B.sh', deploy, 'b68902bd07190b1e518207e82e0ccbc28adf906231de10e8a6733771d557a97b'),
]
pins = {}
for name, gate, original_sha in specs:
    raw = (source / 'infra/hermes' / name).read_bytes()
    text = raw.decode('utf-8')
    assert text.count(begin) == text.count(end) == 1
    assert text.count(gate) == 1
    prefix = text.split(begin)[0]
    assert prefix.endswith('set -euo pipefail\n')
    assert all(line.startswith('#') or line == 'set -euo pipefail' for line in prefix.splitlines())
    assert hashlib.sha256(text.replace(gate, '', 1).encode()).hexdigest() == original_sha
    for old, new in [('/etc/capstone-hermes-guard', str(fixture / 'etc-guard')),
                     ('/var/lib/capstone-automation/hermes-guard', str(fixture / 'state-guard'))]:
        assert text.count(old) == 2
        text = text.replace(old, new)
    (fixture / name).write_text(text)
    pins[name] = hashlib.sha256(raw).hexdigest()
(fixture / 'source-sha.json').write_text(__import__('json').dumps(pins, sort_keys=True))
PY
mkdir "$fixture/bin"
cat > "$fixture/bin/sentinel" <<'SH'
#!/bin/bash
set -euo pipefail
name=${0##*/}
printf '%s\n' "$name" >> "$SENTINEL"
case "$name" in
  id) [[ "$*" == '-u' ]] || exit 97; printf '0\n';;
  du) [[ "$1" == '-h' && "$2" == "$FIXTURE/image.tar" ]] || exit 97; printf '0\t%s\n' "$2";;
  cut) while IFS=$'\t' read -r first rest; do printf '%s\n' "$first"; done;;
  tail) while IFS= read -r line; do printf '%s\n' "$line"; done;;
  docker)
    case "$*" in
      "load -i $FIXTURE/image.tar") printf 'Loaded image: synthetic:test\n';;
      'image inspect nousresearch/hermes-agent:v2026.9.24'*) printf 'synthetic image metadata\n';;
      *) exit 97;;
    esac
    ;;
  *) exit 97;;
esac
SH
chmod 700 "$fixture/bin/sentinel"
for tool in id du cut tail docker dirname touch sed grep chown chmod install wc tr sleep mkdir useradd ssh-keygen cat cp date runuser timeout; do
  ln -s sentinel "$fixture/bin/$tool"
done
: > "$fixture/image.tar"
passed=0
run_one(){
  local expected=$1 script=$2 env_kind=$3; shift 3
  : > "$fixture/sentinel.calls"
  local -a provided=(/usr/bin/env -i PATH="$fixture/bin" FIXTURE="$fixture" SENTINEL="$fixture/sentinel.calls")
  case "$env_kind" in
    both) provided+=(MM_HERMES_ENV="$fixture/absent-env" SOC_READ_TOKEN=synthetic);;
    mm) provided+=(MM_HERMES_ENV="$fixture/absent-env");;
    unset) ;;
    *) return 1;;
  esac
  set +e
  "${provided[@]}" /bin/bash "$fixture/$script" "$@" > "$fixture/stdout" 2> "$fixture/stderr"
  local rc=$?
  set -e
  [[ "$rc" == "$expected" ]] || { printf 'fixture_failed: unexpected_exit\n' >&2; exit 1; }
  passed=$((passed + 1))
}
deny_one(){
  run_one 78 "$@"
  [[ ! -s "$fixture/sentinel.calls" && ! -s "$fixture/stdout" ]]
  [[ "$(<"$fixture/stderr")" == 'Legacy Hermes deployment blocked: managed guard state exists. Review the fixed root prestart path infra/automation/ansible/hermes-prestart-local-b.sh.' ]]
}
load_one(){
  run_one 0 deploy_hermes_B.sh unset load "$fixture/image.tar"
  [[ ! -s "$fixture/stderr" ]]
  [[ "$(<"$fixture/sentinel.calls")" == $'id\ndu\ncut\ndocker\ntail\ndocker\ndocker' ||
     "$(<"$fixture/sentinel.calls")" == $'id\ncut\ndu\ndocker\ntail\ndocker\ndocker' ]]
}
for guard in etc-guard state-guard; do
  for kind in directory file dangling_symlink; do
    case "$kind" in
      directory) mkdir "$fixture/$guard";;
      file) : > "$fixture/$guard";;
      dangling_symlink) ln -s "$fixture/missing-target" "$fixture/$guard";;
    esac
    deny_one deploy_gateway_B.sh unset
    deny_one deploy_gateway_B.sh both
    for action in prep test all; do deny_one deploy_hermes_B.sh unset "$action"; done
    load_one
    if [[ -d "$fixture/$guard" && ! -L "$fixture/$guard" ]]; then rmdir "$fixture/$guard"; else rm "$fixture/$guard"; fi
  done
done
run_one 1 deploy_gateway_B.sh unset
[[ ! -s "$fixture/sentinel.calls" && "$(<"$fixture/stderr")" == *'MM_HERMES_ENV unset'* ]]
run_one 1 deploy_gateway_B.sh mm
[[ ! -s "$fixture/sentinel.calls" && "$(<"$fixture/stderr")" == *'SOC_READ_TOKEN unset'* ]]
run_one 1 deploy_hermes_B.sh unset
[[ "$(<"$fixture/sentinel.calls")" == 'id' && "$(<"$fixture/stdout")" == usage:* ]]
run_one 1 deploy_hermes_B.sh unset invalid
[[ "$(<"$fixture/sentinel.calls")" == 'id' && "$(<"$fixture/stdout")" == usage:* ]]
load_one
[[ "$passed" == 41 ]]
python3 - "$fixture/source-sha.json" "$passed" <<'PY'
import json, pathlib, sys
print(json.dumps({'status':'passed','native_cases':int(sys.argv[2]),'source_sha256':json.loads(pathlib.Path(sys.argv[1]).read_text()),'original_body_bytes_unchanged':True,'production_paths_accessed':False,'external_commands_stubbed':True,'image_load_only_preserved':True}, sort_keys=True))
PY
