<?php
declare(strict_types=1);

namespace PayLoop;

/**
 * Outbound URL policy for partner webhook tests.
 * allow-list of hostnames -> resolve -> every address must be public -> caller connects to the vetted IP.
 */
final class SsrfGuard
{
    private const EXTRA_BLOCKED_V4 = [
        '100.64.0.0/10', '192.0.0.0/24', '192.0.2.0/24', '198.18.0.0/15',
        '198.51.100.0/24', '203.0.113.0/24', '169.254.0.0/16', '127.0.0.0/8',
    ];

    /**
     * @param  callable(string):array<int,string>|null $resolver injectable for tests
     * @return array{scheme:string,host:string,port:int,ip:string,target:string}
     * @throws \InvalidArgumentException with a machine-readable reason
     */
    public static function validate(string $url, ?callable $resolver = null): array
    {
        $p = parse_url($url);
        if ($p === false || !isset($p['scheme'])) {
            throw new \InvalidArgumentException('malformed_url');
        }
        $scheme = strtolower($p['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new \InvalidArgumentException('scheme_not_allowed');
        }
        if (!isset($p['host'])) {
            throw new \InvalidArgumentException('malformed_url');
        }
        if (isset($p['user']) || isset($p['pass'])) {
            throw new \InvalidArgumentException('userinfo_not_allowed');
        }
        $host = strtolower(rtrim($p['host'], '.'));
        if (filter_var(trim($host, '[]'), FILTER_VALIDATE_IP) !== false) {
            throw new \InvalidArgumentException('ip_literal_not_allowed');
        }
        $port = $p['port'] ?? ($scheme === 'https' ? 443 : 80);
        if (!in_array($port, [80, 443], true)) {
            throw new \InvalidArgumentException('port_not_allowed');
        }
        if (!in_array($host, self::allowlist(), true)) {
            throw new \InvalidArgumentException('host_not_allowlisted');
        }

        $ips = ($resolver ?? [self::class, 'resolve'])($host);
        if ($ips === []) {
            throw new \InvalidArgumentException('dns_failure');
        }
        foreach ($ips as $ip) {
            if (!self::isPublic($ip)) {
                throw new \InvalidArgumentException('resolves_to_non_public_ip');
            }
        }

        $target = ($p['path'] ?? '/') . (isset($p['query']) ? '?' . $p['query'] : '');
        return ['scheme' => $scheme, 'host' => $host, 'port' => $port, 'ip' => $ips[0], 'target' => $target];
    }

    public static function isPublic(string $ip): bool
    {
        // IPv4 only: IPv6 (including IPv4-mapped ::ffff:a.b.c.d, NAT64 and 6to4 forms) is rejected outright,
        // because those encodings are a classic way to smuggle a private address past a range filter.
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return false;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false;
        }
        foreach (self::EXTRA_BLOCKED_V4 as $cidr) {
            if (self::inCidr($ip, $cidr)) {
                return false;
            }
        }
        return true;
    }

    /** @return array<int,string> */
    public static function resolve(string $host): array
    {
        $ips = gethostbynamel($host);
        return $ips === false ? [] : $ips;
    }

    /** @return array<int,string> */
    private static function allowlist(): array
    {
        $raw = (string) getenv('PAYLOOP_WEBHOOK_ALLOWLIST');   // empty = deny everything
        return array_values(array_filter(array_map(static fn($h) => strtolower(trim($h)), explode(',', $raw))));
    }

    private static function inCidr(string $ip, string $cidr): bool
    {
        [$net, $bits] = explode('/', $cidr);
        $mask = -1 << (32 - (int) $bits);
        return (ip2long($ip) & $mask) === (ip2long($net) & $mask);
    }
}
