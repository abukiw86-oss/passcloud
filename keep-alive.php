<?php
require_once 'db.php';
require_once 'security.php';

if (isset($_SESSION['uniq'])) {
    // Update session time
    $_SESSION['login_time'] = time();
    echo json_encode(['success' => true]);
} else {
    echo json_encode(['success' => false]);
}
?>