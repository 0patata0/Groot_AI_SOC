#!/usr/bin/env bash
# Existing Groot_C only: publish the small UI using its existing Apache/PHP.
set -euo pipefail
umask 077
test "$(id -u)" = 0 || { echo 'root 권한으로 실행하세요.' >&2; exit 1; }
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
target=/var/www/html/log4shell
state=/var/lib/capstone-log4shell-ui
files=(index.html app.css app.js api.php)

for command in php curl install mktemp sha256sum python3 apache2ctl; do
  command -v "$command" >/dev/null
done
systemctl is-active --quiet apache2
php -r 'exit(PHP_VERSION_ID >= 80100 && extension_loaded("curl") && extension_loaded("session") ? 0 : 1);'
apache2ctl configtest
for file in "${files[@]}"; do
  test -f "$source_dir/public/$file"
  test ! -L "$source_dir/public/$file"
done
php -l "$source_dir/public/api.php"
test -d /var/www/html
test ! -L /var/www/html
if test -e "$target" || test -L "$target"; then
  echo '기존 /var/www/html/log4shell 경로가 있습니다. 덮어쓰지 않고 중단합니다.' >&2
  exit 1
fi
code=$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  -H 'X-Api-Version: capstone-ui-install-check' http://10.200.10.20:8080/)
test "$code" = 200
dvwa_before=$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  http://127.0.0.1/dvwa/login.php)
test "$dvwa_before" = 200

stamp=$(date +%Y%m%dT%H%M%S%z)
receipt="/var/backups/capstone-log4shell-ui/$stamp"
test ! -e "$receipt"
install -d -o root -g root -m 0700 "$receipt"
test ! -L "$state"
install -d -o root -g www-data -m 0750 "$state"
test ! -L "$state/request.lock"
if test ! -e "$state/request.lock"; then
  install -o root -g www-data -m 0660 /dev/null "$state/request.lock"
fi
test -f "$state/request.lock"
test "$(stat -c '%U:%G:%a' "$state/request.lock")" = root:www-data:660

stage=$(mktemp -d /var/www/.log4shell-stage.XXXXXXXX)
published=0
cleanup() {
  code=$?
  trap - EXIT
  if (( code != 0 && published == 1 )); then
    mv -- "$target" "$receipt/failed-public"
    echo "검증 실패: 웹 경로를 회수했습니다. 확인 자료: $receipt" >&2
  fi
  if test -d "$stage"; then rm -rf -- "$stage"; fi
  exit "$code"
}
trap cleanup EXIT
for file in "${files[@]}"; do
  install -o root -g root -m 0644 "$source_dir/public/$file" "$stage/$file"
done
chmod 0755 "$stage"
(cd "$stage" && sha256sum "${files[@]}") > "$receipt/public.sha256"
cp -- "$source_dir/install.sh" "$receipt/install.sh"
mv -- "$stage" "$target"
published=1
curl --fail --silent --show-error --max-time 5 http://127.0.0.1/log4shell/ -o /dev/null
python3 -B "$source_dir/verify.py" http://127.0.0.1/log4shell/ \
  | tee "$receipt/verification.txt"
dvwa_after=$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' \
  http://127.0.0.1/dvwa/login.php)
test "$dvwa_after" = "$dvwa_before"
(cd "$target" && sha256sum -c "$receipt/public.sha256")
printf 'completed_at=%s\ndvwa_before=%s\ndvwa_after=%s\nrestart_count=0\n' \
  "$(date --iso-8601=seconds)" "$dvwa_before" "$dvwa_after" > "$receipt/result.txt"
echo "설치 완료: /log4shell/ (검증 기록: $receipt)"
