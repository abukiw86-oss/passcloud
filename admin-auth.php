<?php
// admin-auth.php - Include this in all admin pages
function requireAdmin() {
    if (!isset($_SESSION['uniq']) || $_SESSION['user_role'] !== 'admin') {
        header("Location: login.php");
        exit;
    }
}

//function logSecurityEvent($event_type, $severity = 'medium', $details = '') {
    global $conn;
    
    $user_id = $_SESSION['uniq'] ?? 'system';
    $ip_address = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    
    $stmt = $conn->prepare(
        "INSERT INTO security_logs (user_id, event_type, ip_address, user_agent, severity, details) 
         VALUES (?, ?, ?, ?, ?, ?)"
    );
    $stmt->bind_param("ssssss", $user_id, $event_type, $ip_address, $user_agent, $severity, $details);
    $stmt->execute();
//}
?>