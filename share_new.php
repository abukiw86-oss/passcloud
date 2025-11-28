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

// Get user's passwords
$passwords = mysqli_query($conn, "SELECT * FROM vault WHERE unique_id = '$user_id' ORDER BY site");

// Share password
if (isset($_POST['share_password'])) {
    $vault_id = intval($_POST['vault_id']);
    $recipient_email = htmlspecialchars(trim($_POST['recipient_email']));
    $access_level = $_POST['access_level'];
    $expires_days = intval($_POST['expires_days']);
    
    // Validate inputs
    if (empty($vault_id) || empty($recipient_email)) {
        $error = "Please select a password and enter recipient email";
    } elseif (!filter_var($recipient_email, FILTER_VALIDATE_EMAIL)) {
        $error = "Please enter a valid email address";
    } else {
        // Check if recipient exists
        $recipient = mysqli_query($conn, "SELECT * FROM users WHERE mail = '$recipient_email'");
        
        if ($recipient->num_rows > 0) {
            $recipient_data = $recipient->fetch_assoc();
            $share_token = bin2hex(random_bytes(16));
            
            // Create direct share
            $expires_sql = $expires_days > 0 ? "DATE_ADD(NOW(), INTERVAL $expires_days DAY)" : "NULL";
            $insert_share = mysqli_query($conn, "
                INSERT INTO password_shares (unique_id, vault_id, shared_with, share_token, access_level, expires_at) 
                VALUES ('$user_id', $vault_id, '{$recipient_data['unique_id']}', '$share_token', '$access_level', $expires_sql)
            ");
            
            if ($insert_share) {
                // Create notification for recipient
                mysqli_query($conn, "
                    INSERT INTO share_notifications (unique_id, share_id) 
                    VALUES ('{$recipient_data['unique_id']}', LAST_INSERT_ID())
                ");
                $success = "Password shared successfully with $recipient_email!";
            } else {
                $error = "Failed to share password. Please try again.";
            }
        } else {
            // Create invitation for non-user
            $share_token = bin2hex(random_bytes(16));
            $expires_sql = $expires_days > 0 ? "DATE_ADD(NOW(), INTERVAL $expires_days DAY)" : "NULL";
            $insert_invite = mysqli_query($conn, "
                INSERT INTO share_invitations (share_token, sender_id, sender_email, recipient_email, vault_id, access_level, expires_at) 
                VALUES ('$share_token', '$user_id', '$email', '$recipient_email', $vault_id, '$access_level', $expires_sql)
            ");
            
            if ($insert_invite) {
                $success = "Invitation sent to $recipient_email! They'll need to create a PassCloud account to access the password.";
            } else {
                $error = "Failed to send invitation. Please try again.";
            }
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
    
    <title>Share Yours - PassCloud</title>
    
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    
    <link rel="stylesheet" href="assets/shan.css?v=<?php echo time(); ?>">
</head>
<body>
    <header>
        <div class="logo">
            <i class="fas fa-cloud"></i>
            PassCloud
        </div>
        
        <a href="share_dashboard.php" class="back-btn">
            <i class="fas fa-arrow-left"></i>
            <span>Back to Sharing</span>
        </a>
    </header>

    <div class="container">
        <div class="page-title">
            <h1><i class="fas fa-share-alt"></i> Share Password</h1>
            <p>Securely share a password with another user</p>
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

        <div class="sharing-section">
            <div class="section-header">
                <i class="fas fa-lock"></i>
                <h2>Share Password Details</h2>
            </div>

            <form method="post">
                <div class="form-group">
                    <label for="vault_id">Select Password to Share</label>
                    <select name="vault_id" id="vault_id" class="form-control" required>
                        <option value="">Choose a password to share...</option>
                        <?php while($pwd = $passwords->fetch_assoc()): ?>
                            <option value="<?php echo $pwd['id']; ?>">
                                <?php echo htmlspecialchars($pwd['site']); ?> - <?php echo htmlspecialchars($pwd['mail']); ?>
                            </option>
                        <?php endwhile; ?>
                    </select>
                    <?php if($passwords->num_rows === 0): ?>
                        <div style="color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-top: 8px;">
                            No passwords found. <a href="vault.php" style="color: var(--accent);">Add passwords to your vault first</a>.
                        </div>
                    <?php endif; ?>
                </div>

                <div class="form-group">
                    <label for="recipient_email">Recipient Email Address</label>
                    <input type="email" name="recipient_email" id="recipient_email" class="form-control" 
                           placeholder="Enter the recipient's email address" required>
                </div>

                <div class="form-group">
                    <label for="access_level">Access Level</label>
                    <select name="access_level" id="access_level" class="form-control">
                        <option value="view">View Only - Can see but not edit the password</option>
                        <option value="edit">View and Edit - Can see and modify the password</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="expires_days">Share Expiration</label>
                    <select name="expires_days" id="expires_days" class="form-control">
                        <option value="0">Never expire</option>
                        <option value="1">1 day</option>
                        <option value="7">7 days</option>
                        <option value="30">30 days</option>
                        <option value="90">90 days</option>
                    </select>
                </div>

                <button type="submit" name="share_password" class="btn btn-primary btn-block" 
                        <?php echo $passwords->num_rows === 0 ? 'disabled' : ''; ?>>
                    <i class="fas fa-share"></i> Share Password
                </button>
            </form>

            <div class="info-box">
                <h4><i class="fas fa-info-circle"></i> How Password Sharing Works</h4>
                <p>
                    • If the recipient has a PassCloud account, they'll see the password immediately in their "Shared with You" section.<br>
                    • If they don't have an account, they'll receive an invitation email to join PassCloud and access the shared password.<br>
                    • You can always revoke access later from the sharing dashboard.
                </p>
            </div>
        </div>
    </div>

    <footer>
        <p>&copy; <?php echo date("Y"); ?> PassCloud — Secure Your Digital Life</p>
    </footer>

   <script src="assets/shan.js?v=<?php echo time(); ?>"></script>
    <script nonce="<?php echo CSP_NONCE; ?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
    </script>
</body>
</html>