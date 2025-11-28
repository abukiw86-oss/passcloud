<?php
require_once 'db.php';
require_once 'security.php';
session_start();
if (!isset($_SESSION['uniq'])) {
    header("Location: log.php");
    exit;
}
require_once 'security.php';

$user_id = $_SESSION['uniq'] ?? 0;

// Get unread notifications count
$unread_count = mysqli_query($conn, "
    SELECT COUNT(*) as count FROM share_notifications 
    WHERE unique_id = '$user_id' AND is_read = 0
")->fetch_assoc()['count'];

// Mark notifications as read
if (isset($_POST['mark_read'])) {
    mysqli_query($conn, "UPDATE share_notifications SET is_read = 1 WHERE unique_id = '$user_id'");
}

// Get recent notifications
$notifications = mysqli_query($conn, "
    SELECT sn.*, ps.share_token, v.site, u.name as sender_name 
    FROM share_notifications sn
    JOIN password_shares ps ON sn.share_id = ps.id
    JOIN vault v ON ps.vault_id = v.id
    JOIN users u ON ps.unique_id = u.unique_id
    WHERE sn.unique_id = '$user_id' 
    ORDER BY sn.created_at DESC 
    LIMIT 10
");

header('Content-Type: application/json');
echo json_encode([
    'unread_count' => $unread_count,
    'notifications' => $notifications->fetch_all(MYSQLI_ASSOC)
]);
?>