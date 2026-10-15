#!/bin/bash
# B operator-only one-off evaluation. Installs nothing; never calls actual tools.
set -euo pipefail
[[ $(uname -s) == Linux && $# == 2 ]] || exit 64
case "$1" in quality|tools) suite=$1;; *) exit 64;; esac
out=$2
[[ $out =~ ^/var/tmp/capstone-promptfoo-20261015/run-[A-Za-z0-9_-]{1,48}$ && ! -e $out && ! -L $out ]] || exit 78
base=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
runtime=/opt/capstone-tools/promptfoo
node=$runtime/node/bin/node
cli=$runtime/app/node_modules/promptfoo/dist/src/entrypoint.js
[[ -x $node && -f $cli ]] || exit 69
/usr/bin/env -i PATH="$runtime/node/bin:/usr/bin:/bin" "$node" -e 'const p=require(process.argv[1]); if(p.version!=="0.124.1")process.exit(1)' "$runtime/app/node_modules/promptfoo/package.json"
umask 077
mkdir -- "$out"
mkdir -- "$out/config" "$out/cache" "$out/logs"
run_env=(/usr/bin/env -i PATH="$runtime/node/bin:/usr/bin:/bin" LANG=C.UTF-8 LC_ALL=C.UTF-8
  PROMPTFOO_DISABLE_TELEMETRY=1 PROMPTFOO_DISABLE_UPDATE=1
  PROMPTFOO_DISABLE_REMOTE_GENERATION=true PROMPTFOO_DISABLE_SHARING=1 PROMPTFOO_SELF_HOSTED=1
  PROMPTFOO_CONFIG_DIR="$out/config" PROMPTFOO_CACHE_PATH="$out/cache" PROMPTFOO_LOG_DIR="$out/logs")
cd -- "$base"
"${run_env[@]}" "$node" "$cli" validate config --config "$suite.json" >"$out/validate.log" 2>&1
set +e
/usr/bin/timeout --signal=TERM --kill-after=5s 960s "${run_env[@]}" "$node" "$cli" eval \
  --config "$suite.json" --no-cache --no-write --no-share --no-progress-bar --no-table \
  --max-concurrency 1 --output "$out/results.json" >"$out/evaluation.log" 2>&1
rc=$?
set -e
printf '{"suite":"%s","exit_code":%d,"model":"qwen3.6:35b","actual_tools_executed":0,"chat_messages_sent":0}\n' "$suite" "$rc" >"$out/execution.json"
cat -- "$out/execution.json"
exit "$rc"
