<?php
declare(strict_types=1);

require __DIR__ . '/../src/autoload.php';

use PayLoop\Handlers;
use PayLoop\{HttpException, Logger, Request, Response};

$rid = bin2hex(random_bytes(8));
$request = Request::fromGlobals();
Logger::init($rid, $request->ip);
header('X-Request-Id: ' . $rid);

register_shutdown_function(static function () use ($request): void {
    Logger::event('request', [
        'method' => $request->method,
        'path'   => $request->path,
        'query'  => $request->decodedQuery(),
        'status' => http_response_code(),
    ]);
});

$routes = [
    'GET /health'               => static fn(Request $r) => Response::json(200, ['status' => 'ok']),
    'POST /login'               => [Handlers\LoginHandler::class, 'handle'],
    'GET /wallet'               => [Handlers\WalletHandler::class, 'handle'],
    'GET /statement'            => [Handlers\StatementHandler::class, 'handle'],
    'GET /receipt'              => [Handlers\ReceiptHandler::class, 'handle'],
    'POST /partner/webhook-test' => [Handlers\WebhookTestHandler::class, 'handle'],
    'POST /transfer'            => [Handlers\TransferHandler::class, 'handle'],
    'GET /admin/users'          => [Handlers\AdminHandler::class, 'users'],
];

try {
    $handler = $routes[$request->method . ' ' . $request->path] ?? null;
    if ($handler === null) {
        throw new HttpException(404, 'not_found');
    }
    $handler($request);
} catch (HttpException $e) {
    Response::json($e->status, ['error' => $e->getMessage(), 'rid' => $rid] + $e->extra);
} catch (\JsonException) {
    Response::json(400, ['error' => 'invalid_json', 'rid' => $rid]);
} catch (\Throwable $e) {
    // Details go to the log (correlated by request id); the client only ever sees a generic error.
    Logger::event('app_error', [
        'type'    => get_class($e),
        'message' => substr($e->getMessage(), 0, 300),
        'where'   => basename($e->getFile()) . ':' . $e->getLine(),
    ]);
    Response::json(500, ['error' => 'internal_error', 'rid' => $rid]);
}
