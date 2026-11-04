<?php
declare(strict_types=1);

// Bypass-oriented unit tests for SsrfGuard (fixed tree). Run: php tests/ssrf_guard_test.php [path/to/app]
$app = $argv[1] ?? __DIR__ . '/../build/fixed';
require $app . '/src/autoload.php';

use PayLoop\SsrfGuard;

putenv('PAYLOOP_WEBHOOK_ALLOWLIST=partner.example.test,rebind.example.test');
$publicResolver = static fn(string $h): array => ['93.184.216.34'];
$fail = 0;

function expect(string $label, string $url, ?string $reason, callable $resolver, int &$fail): void
{
    try {
        SsrfGuard::validate($url, $resolver);
        $got = null;
    } catch (\InvalidArgumentException $e) {
        $got = $e->getMessage();
    }
    $ok = $got === $reason;
    if (!$ok) {
        $fail++;
    }
    printf("[%s] %-52s -> %s%s\n", $ok ? 'PASS' : 'FAIL', $label, $got ?? 'allowed', $ok ? '' : "   (expected " . ($reason ?? 'allowed') . ')');
}

// legitimate
expect('allow-listed https host, public IP', 'https://partner.example.test/hooks/1?x=1', null, $publicResolver, $fail);
// scheme and syntax tricks
expect('file:// scheme', 'file:///etc/passwd', 'scheme_not_allowed', $publicResolver, $fail);
expect('gopher:// scheme', 'gopher://partner.example.test:80/_x', 'scheme_not_allowed', $publicResolver, $fail);
expect('userinfo trick', 'http://partner.example.test@127.0.0.1/', 'userinfo_not_allowed', $publicResolver, $fail);
expect('no scheme', 'partner.example.test/hook', 'malformed_url', $publicResolver, $fail);
// literal IP forms
expect('loopback literal', 'http://127.0.0.1/', 'ip_literal_not_allowed', $publicResolver, $fail);
expect('IPv6 loopback literal', 'http://[::1]/', 'ip_literal_not_allowed', $publicResolver, $fail);
expect('metadata literal', 'http://169.254.169.254/latest/meta-data/', 'ip_literal_not_allowed', $publicResolver, $fail);
expect('decimal-encoded IP (2130706433)', 'http://2130706433/', 'host_not_allowlisted', $publicResolver, $fail);
expect('hex-encoded IP (0x7f.1)', 'http://0x7f.1/', 'host_not_allowlisted', $publicResolver, $fail);
// policy
expect('non-allow-listed host', 'https://evil.example/', 'host_not_allowlisted', $publicResolver, $fail);
expect('allow-listed host on odd port', 'https://partner.example.test:8443/', 'port_not_allowed', $publicResolver, $fail);
// DNS-based bypasses: allow-listed name resolving somewhere private
foreach (['10.0.0.5', '172.16.9.1', '192.168.1.10', '127.0.0.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '198.51.100.7'] as $ip) {
    expect("allow-listed name resolves to $ip", 'https://rebind.example.test/', 'resolves_to_non_public_ip', static fn() => [$ip], $fail);
}
expect('multi-A record with one private address', 'https://rebind.example.test/', 'resolves_to_non_public_ip', static fn() => ['93.184.216.34', '10.0.0.5'], $fail);
expect('IPv6 loopback from DNS', 'https://rebind.example.test/', 'resolves_to_non_public_ip', static fn() => ['::1'], $fail);
expect('IPv4-mapped IPv6 loopback from DNS', 'https://rebind.example.test/', 'resolves_to_non_public_ip', static fn() => ['::ffff:127.0.0.1'], $fail);
expect('DNS failure', 'https://rebind.example.test/', 'dns_failure', static fn() => [], $fail);
// deny-by-default
putenv('PAYLOOP_WEBHOOK_ALLOWLIST=');
expect('empty allow-list denies everything', 'https://partner.example.test/', 'host_not_allowlisted', $publicResolver, $fail);

echo $fail === 0 ? "\nall SSRF guard cases passed\n" : "\n$fail case(s) FAILED\n";
exit($fail === 0 ? 0 : 1);
