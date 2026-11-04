<?php
declare(strict_types=1);

namespace PayLoop;

final class Request
{
    /**
     * @param array<string,mixed>  $query
     * @param array<string,string> $headers
     */
    private function __construct(
        public readonly string $method,
        public readonly string $path,
        public readonly array $query,
        public readonly string $rawQuery,
        public readonly array $headers,
        public readonly string $ip,
        private readonly string $body,
    ) {
    }

    public static function fromGlobals(): self
    {
        $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (str_starts_with((string) $key, 'HTTP_')) {
                $headers[strtolower(str_replace('_', '-', substr((string) $key, 5)))] = (string) $value;
            }
        }

        // X-Forwarded-For is honoured only when the direct peer is the configured trusted proxy.
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
        $trusted = getenv('PAYLOOP_TRUSTED_PROXY');
        if ($trusted !== false && $trusted !== '' && $ip === $trusted && isset($headers['x-forwarded-for'])) {
            $first = trim(explode(',', $headers['x-forwarded-for'])[0]);
            if (filter_var($first, FILTER_VALIDATE_IP) !== false) {
                $ip = $first;
            }
        }

        $body = substr((string) file_get_contents('php://input'), 0, 65536);

        return new self(
            strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')),
            $path,
            $_GET,
            (string) ($_SERVER['QUERY_STRING'] ?? ''),
            $headers,
            $ip,
            $body,
        );
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    /** @return array<string,mixed> */
    public function json(): array
    {
        $data = json_decode($this->body, true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            throw new HttpException(400, 'invalid_json');
        }
        return $data;
    }

    public function bearer(): ?string
    {
        $h = $this->header('authorization');
        if ($h !== null && preg_match('/^Bearer\s+(\S+)$/i', $h, $m) === 1) {
            return $m[1];
        }
        return null;
    }

    public function decodedQuery(): string
    {
        return substr(urldecode($this->rawQuery), 0, 512);
    }
}
