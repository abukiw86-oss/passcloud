<?php
require 'db.php'; // database connection
require_once 'security.php'; 



// At the top of login.php - after security.php include
if (isset($_GET['error']) && $_GET['error'] === 'session_expired') {
    $error = "Your session has expired. Please login again.";
}


// ================= LOGIN =================
if (isset($_POST['sign'])) {
    $mail = htmlspecialchars($_POST['inputmail']);
    $pass = $_POST['inputpass'];

    // Validate password length
    if (strlen($pass) < 6) {
        $error = "Password must contain at least six characters";
    } else {
        $stmt = $conn->prepare("SELECT * FROM users WHERE mail = ?");
        $stmt->bind_param("s", $mail);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();

            // Check if account is banned
            if (isset($user['status']) && $user['status'] === 'banned') {
                $error = "This account has been suspended. Please contact support.";
                logSecurityEvent('login_attempt_banned', 'high', "Attempted login to banned account: $mail");
            }
            // Check if account is active and verify password
            elseif ((!isset($user['status']) || $user['status'] === 'active') && password_verify($pass, $user['pass'])) {
                session_start();
                // Regenerate session ID for security
                session_regenerate_id(true);
                $_SESSION['uniq'] = $user['unique_id'];
                $_SESSION['login_time'] = time();
                $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
                $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
                $_SESSION['user_role'] = $user['role'] ?? 'user'; // Add role to session

                // Update last login
                $update_stmt = $conn->prepare("UPDATE users SET last_login = NOW() WHERE unique_id = ?");
                $update_stmt->bind_param("s", $user['unique_id']);
                $update_stmt->execute();
                $update_stmt->close();

                // Log successful login
                logSecurityEvent('login_success', 'low', "User logged in successfully");

                // Redirect based on role
                if (($_SESSION['user_role'] === 'admin')) {
                    header('location: admin.php');
                } else {
                    header('location: security_quesions.php');

// In your login.php - after successful login:
if (password_verify($pass, $user['pass'])) {
    session_start();
    session_regenerate_id(true);
    $_SESSION['uniq'] = $user['unique_id'];
    $_SESSION['login_time'] = time(); // ADD THIS LINE
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
    $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
    $_SESSION['user_role'] = $user['role'] ?? 'user';
    
    header('location: security_quesions.php');
    exit;
}
                }
                exit;
            } else {
                $error = "Invalid email or password!";
                
                // Log failed attempt
                logSecurityEvent('login_failed', 'medium', "Failed login attempt for: $mail");
                
                // Implement rate limiting
                if (!checkRateLimit('login_attempt_' . $_SERVER['REMOTE_ADDR'], 5, 900)) {
                    $error = "Too many failed attempts. Please try again in 15 minutes.";
                    logSecurityEvent('rate_limit_exceeded', 'high', "Rate limit exceeded for IP: " . $_SERVER['REMOTE_ADDR']);
                }
            }
        } else {
            $error = "Invalid email or password!";
            logSecurityEvent('login_failed', 'medium', "Attempted login to non-existent account: $mail");
        }
        $stmt->close();
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
    
    <title>Welcome back - PassCloud</title>
    
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    
    <link rel="stylesheet" href="assets/log.css?v=<?php echo time(); ?>">
</head>
<body>
  <?php if(isset($error)): ?>
    <div class="error">
      <i class="fas fa-exclamation-circle"></i>
      <?php echo htmlspecialchars($error); ?>
    </div>
  <?php endif; ?>

  <div class="top">
    <p>For security reasons, please login again after registration</p>
  </div>
  
  <div class="card1" id="card1">
    <div class="logo">
      <i class="fas fa-cloud"></i>
      <h1>PassCloud</h1>
    </div>
    
    <h2>Welcome Back</h2>
    
    <form action="" method="post" id="loginForm">
      <div class="input-group">
        <i class="fas fa-envelope input-icon"></i>
        <input type="email" placeholder="you@example.com" required name="inputmail" id="inputmail">
      </div>
      
      <div class="input-group">
        <i class="fas fa-lock input-icon"></i>
        <input type="password" placeholder="Enter password (min. 6 characters)" required name="inputpass" id="inputpass" minlength="6">
        <div class="password-requirements">Password must be at least 6 characters long</div>
      </div>
      
      <button type="submit" class="btn btn-primary" name="sign" id="signBtn">Sign In</button>
    </form>

    <div class="links">
      <a href="forget_password.php">Forgot Password?</a>
    </div>
    
    <div id="create">
      <p>Don't have an account?</p>
      <a href="signup.php">Create Account</a>
    </div>
  </div>


   <script nonce="<?php echo CSP_NONCE; ?>" src="assets/log.js?v=<?php echo time(); ?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
    </script>
</body>
</html>