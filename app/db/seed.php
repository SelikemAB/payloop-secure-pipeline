<?php
declare(strict_types=1);

require __DIR__ . '/../src/autoload.php';

use PayLoop\{Db, PasswordHasher};

Db::migrate();
$pdo = Db::pdo();
if ((int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn() > 0) {
    echo "already seeded\n";
    exit(0);
}

// Fictional demo data only. Wallet ids follow insertion order: alice=1 bob=2 carol=3 dave=4 admin=5.
$seed = [
    ['alice', 'alice-demo-pw', 'customer', 100000],
    ['bob',   'bob-demo-pw',   'customer',  50000],
    ['carol', 'carol-demo-pw', 'customer',  75000],
    ['dave',  'dave-demo-pw',  'customer',  20000],
    ['admin', 'admin-demo-pw', 'admin',         0],
];
foreach ($seed as [$name, $pw, $role, $balance]) {
    $pdo->prepare('INSERT INTO users(username, pass_hash, role) VALUES (?, ?, ?)')
        ->execute([$name, PasswordHasher::hash($pw), $role]);
    $uid = (int) $pdo->lastInsertId();
    $pdo->prepare('INSERT INTO wallets(owner_id, balance_minor) VALUES (?, ?)')->execute([$uid, $balance]);
}
echo "seeded " . count($seed) . " users\n";
