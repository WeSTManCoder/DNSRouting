<?php
// PHP 8+. Publish only binaries and checksums controlled by the administrator.
// Example: releases/1.0.11/dnsrouting-linux-arm64
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
$version = trim(file_get_contents(__DIR__ . '/latest.txt'));
if (!preg_match('/^\d+(?:\.\d+){1,3}$/', $version)) {
    http_response_code(503); echo json_encode(['error' => 'Invalid release version']); exit;
}
$arch = $_GET['arch'] ?? '';
$allowed = ['amd64','386','arm','arm64','mips','mipsle','mips64','mips64le','mips-softfloat','mipsle-softfloat'];
if (!in_array($arch, $allowed, true)) {
    http_response_code(400); echo json_encode(['error' => 'Unsupported architecture']); exit;
}
$file = "releases/$version/dnsrouting-linux-$arch";
$absolute = __DIR__ . '/' . $file;
if (!is_file($absolute)) {
    http_response_code(404); echo json_encode(['error' => 'No binary for this architecture']); exit;
}
$sha = hash_file('sha256', $absolute);
echo json_encode([
    'version' => $version,
    'arch' => $arch,
    'url' => 'https://dnsrouting.gm-world.ru/packages/dnsrouting/' . $file,
    'sha256' => $sha
], JSON_UNESCAPED_SLASHES);
