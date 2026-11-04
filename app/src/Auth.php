<?php
declare(strict_types=1);

namespace PayLoop;

final class Auth
{
    /** @param array<string,mixed> $user */
    public static function issueToken(array $user): string
    {
        $payload = self::b64(json_encode([
            'sub'  => (int) $user['id'],
            'usr'  => $user['username'],
            'role' => $user['role'],
            'exp'  => time() + Config::tokenTtl(),
        ], JSON_THROW_ON_ERROR));
        return $payload . '.' . hash_hmac('sha256', $payload, Config::tokenSecret());
    }

    /** @return array<string,mixed>|null */
    public static function verifyToken(?string $token): ?array
    {
        if ($token === null || substr_count($token, '.') !== 1) {
            return null;
        }
        [$payload, $sig] = explode('.', $token, 2);
        if (!hash_equals(hash_hmac('sha256', $payload, Config::tokenSecret()), $sig)) {
            Logger::event('auth_token_invalid', ['reason' => 'bad_signature']);
            return null;
        }
        $claims = json_decode(self::unb64($payload), true);
        if (!is_array($claims) || (int) ($claims['exp'] ?? 0) < time()) {
            Logger::event('auth_token_invalid', ['reason' => 'expired_or_malformed']);
            return null;
        }
        return $claims;
    }

    /** @return array<string,mixed> */
    public static function requireUser(Request $request): array
    {
        $claims = self::verifyToken($request->bearer());
        if ($claims === null) {
            throw new HttpException(401, 'unauthorized');
        }
        Logger::setUser((string) $claims['usr']);
        return $claims;
    }

    private static function b64(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    private static function unb64(string $s): string
    {
        return (string) base64_decode(strtr($s, '-_', '+/'), true);
    }
}
