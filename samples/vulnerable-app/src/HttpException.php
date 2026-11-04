<?php
declare(strict_types=1);

namespace PayLoop;

final class HttpException extends \RuntimeException
{
    /** @param array<string,mixed> $extra */
    public function __construct(public readonly int $status, string $code, public readonly array $extra = [])
    {
        parent::__construct($code);
    }
}
