<?php
declare(strict_types=1);

// A small adapter for the existing lab. The destination and header name are fixed.
const LAB_URL = 'http://10.200.10.20:8080/';
const RATE_FILE = '/var/lib/capstone-log4shell-ui/request.lock';
const MAX_BODY = 8192;
date_default_timezone_set('Asia/Seoul');
ini_set('display_errors', '0');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_cache_limiter('');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
header('Referrer-Policy: no-referrer');

function reply(int $status, array $body): never {
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function reject(int $status, string $message): never {
    reply($status, ['ok' => false, 'error' => $message]);
}

$method = $_SERVER['REQUEST_METHOD'] ?? '';
if ($method !== 'GET' && $method !== 'POST') {
    header('Allow: GET, POST');
    reject(405, '지원하지 않는 요청 방식입니다.');
}
if (!extension_loaded('curl')) {
    reject(503, '실습 요청 기능을 사용할 수 없습니다. 관리자에게 알려 주세요.');
}

// TLS terminates at chatproxy, which always sets this hint on its HTTPS route.
// The hint only opts into a stricter Secure cookie; it grants no trust or access.
// A forged HTTP hint cannot plant the __Secure- cookie in a browser. Never use
// this hint for authorization, redirects, or deciding whether a peer is trusted.
$secureSession = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || ($_SERVER['HTTP_X_GROOT_LAB_TLS'] ?? '') === '1';
// Do not reuse the legacy name: an existing Secure cookie blocks HTTP updates.
session_name($secureSession ? '__Secure-groot_log4shell_ui_https' : 'groot_log4shell_ui_http');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/log4shell/',
    'secure' => $secureSession,
    'httponly' => true,
    'samesite' => 'Strict',
]);
if (!session_start()) {
    reject(503, '실습 세션을 시작하지 못했습니다.');
}
if (!isset($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

if ($method === 'GET') {
    if (($_GET['action'] ?? '') !== 'bootstrap' || count($_GET) !== 1) {
        session_write_close();
        reject(400, '올바른 실습 화면에서 요청해 주세요.');
    }
    $csrf = $_SESSION['csrf'];
    session_write_close();
    reply(200, [
        'ok' => true,
        'csrf' => $csrf,
        'lab' => ['name' => 'Log4Shell', 'target' => LAB_URL, 'timezone' => 'Asia/Seoul'],
    ]);
}

if ($_GET !== []) {
    session_write_close();
    reject(400, '지원하지 않는 요청 옵션입니다.');
}
if (!hash_equals($_SESSION['csrf'], (string)($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ''))) {
    session_write_close();
    reject(403, '실습 세션을 확인하지 못했습니다. 화면을 새로고침해 주세요.');
}
if (strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0])) !== 'application/json') {
    session_write_close();
    reject(415, 'JSON 형식의 요청이 필요합니다.');
}
if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 2048) {
    session_write_close();
    reject(413, '요청이 너무 큽니다.');
}
$raw = file_get_contents('php://input', false, null, 0, 2049);
if ($raw === false || strlen($raw) > 2048) {
    session_write_close();
    reject(413, '요청이 너무 큽니다.');
}
try {
    $input = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
} catch (JsonException $e) {
    session_write_close();
    reject(400, '요청 내용을 읽을 수 없습니다.');
}
if (!is_array($input) || array_is_list($input) || array_diff(array_keys($input), ['mode', 'api_version'])) {
    session_write_close();
    reject(400, '지원하지 않는 요청 항목입니다.');
}
$mode = $input['mode'] ?? null;
$version = $input['api_version'] ?? '';
if (!in_array($mode, ['normal', 'missing-header'], true) || !is_string($version)) {
    session_write_close();
    reject(400, '실습 모드와 헤더 값을 확인해 주세요.');
}
if (($mode === 'normal' && !preg_match('/\A[A-Za-z0-9._ -]{1,64}\z/D', $version)) ||
    ($mode === 'missing-header' && $version !== '' && !preg_match('/\A[A-Za-z0-9._ -]{1,64}\z/D', $version))) {
    session_write_close();
    reject(400, '헤더는 영문, 숫자, 공백, 점, 밑줄, 하이픈으로 1~64자 입력해 주세요.');
}
if (microtime(true) - (float)($_SESSION['last_request'] ?? 0) < 1.0) {
    session_write_close();
    header('Retry-After: 1');
    reject(429, '잠시 기다린 뒤 다시 요청해 주세요.');
}
$_SESSION['last_request'] = microtime(true);
session_write_close();

// One in-flight request and at least one second between requests across all sessions.
$lock = @fopen(RATE_FILE, 'r+');
if ($lock === false) {
    reject(503, '실습 요청 제어를 준비하지 못했습니다. 관리자에게 알려 주세요.');
}
if (!flock($lock, LOCK_EX | LOCK_NB)) {
    fclose($lock);
    header('Retry-After: 1');
    reject(429, '다른 실습 요청을 처리 중입니다. 잠시 후 다시 시도해 주세요.');
}
$last = (float)stream_get_contents($lock, 64);
if (microtime(true) - $last < 1.0) {
    flock($lock, LOCK_UN);
    fclose($lock);
    header('Retry-After: 1');
    reject(429, '잠시 기다린 뒤 다시 요청해 주세요.');
}
$tick = sprintf('%.6f', microtime(true));
if (!rewind($lock) || !ftruncate($lock, 0) || fwrite($lock, $tick) !== strlen($tick) || !fflush($lock)) {
    flock($lock, LOCK_UN);
    fclose($lock);
    reject(503, '실습 요청 제어 상태를 저장하지 못했습니다. 관리자에게 알려 주세요.');
}

$id = 'lab-' . bin2hex(random_bytes(6));
$started = date(DATE_ATOM);
$headers = ['Accept: text/plain, application/json', 'X-Request-ID: ' . $id];
if ($mode === 'normal') {
    $headers[] = 'X-Api-Version: ' . $version;
}
$body = '';
$overflow = false;
$curl = curl_init(LAB_URL);
curl_setopt_array($curl, [
    CURLOPT_HTTPGET => true,
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_USERAGENT => 'Groot-Log4Shell-Lab-UI/1.0',
    CURLOPT_CONNECTTIMEOUT_MS => 1500,
    CURLOPT_TIMEOUT_MS => 4000,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_MAXREDIRS => 0,
    CURLOPT_PROTOCOLS => CURLPROTO_HTTP,
    CURLOPT_PROXY => '',
    CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body, &$overflow): int {
        if (strlen($body) + strlen($chunk) > MAX_BODY) {
            $overflow = true;
            return 0;
        }
        $body .= $chunk;
        return strlen($chunk);
    },
]);
$result = curl_exec($curl);
$status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
$duration = round((float)curl_getinfo($curl, CURLINFO_TOTAL_TIME) * 1000, 1);
$type = (string)(curl_getinfo($curl, CURLINFO_CONTENT_TYPE) ?: '');
curl_close($curl);
flock($lock, LOCK_UN);
fclose($lock);

if ($result === false || $status === 0 || $overflow) {
    reject(502, $overflow
        ? '실습 서버의 응답이 표시 한도(8 KiB)를 초과했습니다.'
        : '실습 서버에서 응답을 받지 못했습니다. 잠시 후 다시 시도해 주세요.');
}
$interpretation = '응답을 수신했습니다. 아래 HTTP 상태와 본문을 확인하세요.';
if ($mode === 'normal' && $status === 200) {
    $interpretation = 'API 버전 헤더를 포함한 요청이 정상 처리됐습니다. 이 결과만으로 취약점 재현 성공을 판단하지 않습니다.';
} elseif ($mode === 'missing-header' && $status === 400) {
    $interpretation = '필수 X-Api-Version 헤더가 없어 앱이 HTTP 400을 반환했습니다. 헤더 누락 실습에서 기대하는 결과입니다.';
}
reply(200, [
    'ok' => true,
    'request' => [
        'id' => $id,
        'mode' => $mode,
        'header_name' => 'X-Api-Version',
        'header_value' => $mode === 'normal' ? $version : null,
        'started_at' => $started,
        'target' => LAB_URL,
    ],
    'response' => ['status' => $status, 'body' => $body, 'content_type' => $type],
    'duration_ms' => $duration,
    'interpretation' => $interpretation,
]);
