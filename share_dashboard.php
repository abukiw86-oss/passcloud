<?php
require_once 'db.php';
require_once 'security.php';
session_start();
if (!isset($_SESSION['uniq'])) {
    header("Location: log.php");
    exit;
}

$user_id = $_SESSION['uniq'] ?? 0;
$select = mysqli_query($conn, "SELECT * FROM users WHERE unique_id = '$user_id'");
if($select->num_rows > 0) {
    $data = mysqli_fetch_array($select);
    $name = $data['name'];
    $email = $data['mail'];
}

$success = '';
$error = '';

// Get shared passwords (both sent and received)
$shared_sent = mysqli_query($conn, "
    SELECT ps.*, v.site, v.mail, u.name as recipient_name 
    FROM password_shares ps 
    JOIN vault v ON ps.vault_id = v.id 
    JOIN users u ON ps.shared_with = u.unique_id 
    WHERE ps.unique_id = '$user_id' 
    ORDER BY ps.created_at DESC
");

$shared_received = mysqli_query($conn, "
    SELECT ps.*, v.site, v.mail, v.pass, u.name as sender_name 
    FROM password_shares ps 
    JOIN vault v ON ps.vault_id = v.id 
    JOIN users u ON ps.unique_id = u.unique_id 
    WHERE ps.shared_with = '$user_id' AND ps.is_active = 1 
    ORDER BY ps.created_at DESC
");

// Get pending invitations
$pending_invitations = mysqli_query($conn, "
    SELECT si.*, v.site 
    FROM share_invitations si 
    JOIN vault v ON si.vault_id = v.id 
    WHERE si.recipient_email = '$email' AND si.status = 'pending'
");

// Revoke share
if (isset($_POST['revoke_share'])) {
    $share_id = intval($_POST['share_id']);
    $revoke = mysqli_query($conn, "UPDATE password_shares SET is_active = 0 WHERE id = $share_id AND unique_id = '$user_id'");
    if ($revoke) {
        $success = "Password share revoked successfully!";
    } else {
        $error = "Failed to revoke share.";
    }
}

// Accept invitation
if (isset($_POST['accept_invitation'])) {
    $token = htmlspecialchars($_POST['share_token']);
    $invitation = mysqli_query($conn, "SELECT * FROM share_invitations WHERE share_token = '$token' AND recipient_email = '$email'");
    
    if ($invitation->num_rows > 0) {
        $invite = $invitation->fetch_assoc();
        
        // Create active share
        $insert_share = mysqli_query($conn, "
            INSERT INTO password_shares (unique_id, vault_id, shared_with, share_token, access_level, expires_at) 
            VALUES ('{$invite['sender_id']}', {$invite['vault_id']}, '$user_id', '$token', '{$invite['access_level']}', '{$invite['expires_at']}')
        ");
        
        if ($insert_share) {
            mysqli_query($conn, "UPDATE share_invitations SET status = 'accepted' WHERE share_token = '$token'");
            $success = "Password share accepted successfully!";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <!-- Security Meta Tags -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'nonce-<?php echo CSP_NONCE; ?>' https://cdnjs.cloudflare.com; style-src 'self' 'nonce-<?php echo CSP_NONCE; ?>' https://cdnjs.cloudflare.com 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://cdnjs.cloudflare.com;">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
    
    <title>Share password - PassCloud</title>
    
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    
    <link rel="stylesheet" href="assets/shad.css?v=<?php echo time(); ?>">
</head>
<body>
    <header>
        <div class="logo">
            <i class="fas fa-cloud"></i>
            PassCloud
        </div>
        <a href="dashboard.php" class="back-btn">
            <i class="fas fa-arrow-left"></i>
            <span>Back to Dashboard</span>
        </a>
    </header>

    <div class="container">
        <div class="page-title">
            <h1><i class="fas fa-share-alt"></i> Password Sharing</h1>
            <p>Securely share passwords with other PassCloud users</p>
        </div>

        <?php if(isset($success)): ?>
            <div class="message success">
                <i class="fas fa-check-circle"></i>
                <?php echo $success ?>
            </div>
        <?php endif; ?>

        <?php if(isset($error)): ?>
            <div class="message error">
                <i class="fas fa-exclamation-circle"></i>
                <?php echo $error ?>
            </div>
        <?php endif; ?>
             <!-- Shared With Others -->
        <div class="sharing-section">
            <div class="section-header">
                <h2><i class="fas fa-share-square"></i> Shared by You</h2>
            </div>

            <div class="share-list">
                <?php if($shared_sent->num_rows > 0): ?>
                    <?php while($share = $shared_sent->fetch_assoc()): ?>
                        <div class="share-item">
                            <div class="share-info">
                                <h4><?php echo htmlspecialchars($share['site']); ?></h4>
                                <div class="share-meta">
                                    Shared with: <?php echo htmlspecialchars($share['recipient_name']); ?> • 
                                    Access: <span class="access-badge access-<?php echo $share['access_level']; ?>">
                                        <?php echo ucfirst($share['access_level']); ?>
                                    </span> • 
                                    Shared on: <?php echo date('M j, Y', strtotime($share['created_at'])); ?>
                                </div>
                            </div>
                           <form method="POST" action="">
        <input type="hidden" name="csrf_token" value="<?php echo CSRF_TOKEN; ?>" style="display: inline;">
                                <input type="hidden" name="share_id" value="<?php echo $share['id']; ?>">
                                <button type="submit" name="revoke_share" class="btn btn-danger">
                                    <i class="fas fa-times"></i> Revoke
                                </button>
                            </form>
                        </div>
                    <?php endwhile; ?>
                <?php else: ?>
                    <div class="empty-state">
                        <i class="fas fa-share-alt"></i>
                        <p>You haven't shared any passwords yet</p>
                        <a href="share_new.php" class="btn btn-primary" style="margin-top: 15px;">
                            <i class="fas fa-plus"></i> Share Your First Password
                        </a>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        <!-- Updated Sharing Statistics with Notification Bell -->
<div class="sharing-stats">
    <div class="stat-card">
        <div class="stat-number"><?php echo $shared_sent->num_rows; ?></div>
        <div>Passwords Shared</div>
    </div>
    <div class="stat-card">
        <div class="stat-number"><?php echo $shared_received->num_rows; ?></div>
        <div>Passwords Received</div>
    </div>
    <div class="stat-card">
        <div class="stat-number" id="notificationCount"><?php echo $pending_invitations->num_rows; ?></div>
        <div>Pending Invitations</div>
    </div>
    <div class="stat-card">
        <div style="display: flex; align-items: center; justify-content: center; gap: 15px;">
            <a href="share_new.php" class="btn btn-primary">
                <i class="fas fa-plus"></i> Share New
            </a>
            <!-- Notification Bell -->
            <div class="notification-bell" id="notificationBell">
                <i class="fas fa-bell"></i>
                <span class="notification-badge" id="liveNotificationCount">0</span>
            </div>
        </div>
    </div>
</div>

<!-- Add Notification Panel -->
<div class="notification-panel" id="notificationPanel">
    <div class="notification-header">
        <h3><i class="fas fa-bell"></i> Notifications</h3>
        <button class="btn btn-sm" onclick="markAllRead()">Mark All Read</button>
    </div>
    <div class="notification-list" id="notificationList">
        <!-- Notifications will be loaded here -->
    </div>
</div>
        <!-- Shared With You -->
        <div class="sharing-section">
            <div class="section-header">
                <h2><i class="fas fa-inbox"></i> Shared to You</h2>
            </div>

            <div class="share-list">
                <?php if($shared_received->num_rows > 0): ?>
                    <?php while($share = $shared_received->fetch_assoc()): ?>
                        <div class="share-item">
                            <div class="share-info">
                                <h4><?php echo htmlspecialchars($share['site']); ?></h4>
                                <div class="share-meta">
                                    Shared by: <?php echo htmlspecialchars($share['sender_name']); ?> • 
                                    Username: <?php echo htmlspecialchars($share['mail']); ?> • 
                                    Access: <span class="access-badge access-<?php echo $share['access_level']; ?>">
                                        <?php echo ucfirst($share['access_level']); ?>
                                    </span>
                                </div>
                            </div>
                            <div style="display: flex; gap: 10px; align-items: center;">
                                <span class="pwd" data-password="<?php echo htmlspecialchars($share['pass']); ?>">•••••••</span>
                                <button class="btn" onclick="togglePassword(this)" style="background: var(--accent);">
                                    <i class="fas fa-eye"></i>
                                </button>
                                <button class="btn btn-primary" onclick="copyPassword(this, '<?php echo htmlspecialchars($share['pass']); ?>')">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                        </div>
                    <?php endwhile; ?>
                <?php else: ?>
                    <div class="empty-state">
                        <i class="fas fa-inbox"></i>
                        <p>No passwords have been shared with you yet</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Pending Invitations -->
        <?php if($pending_invitations->num_rows > 0): ?>
        <div class="sharing-section">
            <div class="section-header">
                <h2><i class="fas fa-envelope"></i> Pending Invitations</h2>
            </div>

            <div class="share-list">
                <?php while($invite = $pending_invitations->fetch_assoc()): ?>
                    <div class="share-item">
                        <div class="share-info">
                            <h4><?php echo htmlspecialchars($invite['site']); ?></h4>
                            <div class="share-meta">
                                From: <?php echo htmlspecialchars($invite['sender_email']); ?> • 
                                Sent: <?php echo date('M j, Y', strtotime($invite['created_at'])); ?>
                            </div>
                        </div>
                        <form method="post">
                            <input type="hidden" name="share_token" value="<?php echo $invite['share_token']; ?>">
                            <button type="submit" name="accept_invitation" class="btn btn-success">
                                <i class="fas fa-check"></i> Accept
                            </button>
                        </form>
                    </div>
                <?php endwhile; ?>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <footer>
        <p>&copy; <?php echo date("Y"); ?> PassCloud — Secure Your Digital Life</p>
    </footer>

 <script src="assets/shad.js?v=<?php echo time(); ?>"></script>
  <script nonce="<?php echo CSP_NONCE; ?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
    </script>
</body>
</html>