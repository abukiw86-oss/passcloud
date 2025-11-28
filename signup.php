  <?php
  require "db.php";
  require_once 'security.php';
// ================= SIGNUP =================
if (isset($_POST['log'])) {
    $name = htmlspecialchars(trim($_POST['name']));
    $mail = htmlspecialchars(trim($_POST['mail']));
    $pass = htmlspecialchars($_POST ['pass']);
    
    // Validate inputs
    if (empty($name) || empty($mail) || empty($pass)) {
        $error = "All fields are required!";
    } elseif (strlen($name) < 2) {
        $error = "Name must be at least 2 characters long!";
    } elseif (!filter_var($mail, FILTER_VALIDATE_EMAIL)) {
        $error = "Please enter a valid email address!";
    } elseif (strlen($pass) < 6) {
        $error = "Password must contain at least six characters!";
    } else {
        $hashed_password = password_hash($pass, PASSWORD_DEFAULT);
        $time_var = date('Y-m-d H:i:s');
        $user_id = uniqid(); 
        $type = "user"; // default role

        // check if email already exists
        $check = $conn->prepare("SELECT id FROM users WHERE mail = ?");
        $check->bind_param("s", $mail);
        $check->execute();
        $check->store_result();      

        if ($check->num_rows > 0) {
            $error = "Email already exists!";
        } else {
            $stmt = $conn->prepare("INSERT INTO users (name, unique_id, mail, role, pass, date) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("ssssss", $name, $user_id, $mail, $type, $hashed_password, $time_var);
            
            if ($stmt->execute()) {
                session_start();
                // Regenerate session ID for security
                session_regenerate_id(true);
                $_SESSION['uniq'] = $user_id;
                $_SESSION['login_time'] = time();
                $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
                $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
                
                header("location: log.php");
                exit;
            } else {
                $error = "Database error: " . $stmt->error;
            }
            $stmt->close();
        }
        $check->close();
    }
}

if(isset($error)) {
    echo "<div class='error'>".htmlspecialchars($error)."</div>";
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
    
    <title>Create Account - PassCloud</title>
    
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    
    <link rel="stylesheet" href="assets/sign.css?v=<?php echo time(); ?>">
</head>
<body>


  <div class="card2" id="card2">
    <div class="logo">
      <i class="fas fa-cloud"></i>
      <h1>PassCloud</h1>
    </div>
    
    <h2>Create Your Account</h2>
    
    <form action="" method="post">
      <div class="input-group">
        <i class="fas fa-user input-icon"></i>
        <input type="text" placeholder="Full Name" required name="name">
      </div>
      
      <div class="input-group">
        <i class="fas fa-envelope input-icon"></i>
        <input type="email" placeholder="you@example.com" required name="mail" id="email">
      </div>
      
      <div class="input-group">
        <i class="fas fa-lock input-icon"></i>
        <input id="passs" type="password" placeholder="Create Password" name="pass" required id="pass">
      </div>
      
      <div class="strength">
        <div class="bar" id="bar"></div>
      </div>
      
      <div class="password-requirements">
        <div class="requirement" id="length-req">
          <i class="fas fa-circle"></i>
          <span>At least 8 characters</span>
        </div>
        <div class="requirement" id="uppercase-req">
          <i class="fas fa-circle"></i>
          <span>One uppercase letter</span>
        </div>
        <div class="requirement" id="number-req">
          <i class="fas fa-circle"></i>
          <span>One number</span>
        </div>
        <div class="requirement" id="special-req">
          <i class="fas fa-circle"></i>
          <span>One special character</span>
        </div>
      </div>
      
      <button type="submit" class="btn btn-primary" name="log">Create Account</button>
    </form>

    <div class="login-link">
      Already have an account? <a href="log.php">Login</a>
    </div>
  </div>
  <script src="assets/sign.js?v=<?php echo time(); ?>"></script>
   <script nonce="<?php echo CSP_NONCE; ?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
    </script>
</body>
</html>