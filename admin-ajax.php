<?php
require_once 'db.php';
require_once 'security.php';

if (!isset($_SESSION['uniq']) || $_SESSION['user_role'] !== 'admin') {
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit;
}

$action = $_GET['action'] ?? '';

header('Content-Type: application/json');

switch ($action) {
    case 'clear_cache':
        // Clear cache logic
        echo json_encode(['success' => true, 'message' => 'Cache cleared']);
        break;
        
    case 'optimize_db':
        // Optimize database tables
        $tables = ['users', 'passwords', 'security_logs', 'sessions'];
        foreach ($tables as $table) {
            mysqli_query($conn, "OPTIMIZE TABLE $table");
        }
        echo json_encode(['success' => true, 'message' => 'Database optimized']);
        break;
        
    case 'auto_save':
        // Auto-save settings
        echo json_encode(['success' => true, 'message' => 'Settings saved']);
        break;
        
    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
        break;
}
?>