<?php
require_once 'db.php';
require_once 'security.php';
session_start();


$start_date = $_GET['start_date'] ?? date('Y-m-01');
$end_date = $_GET['end_date'] ?? date('Y-m-t');

if(!isset($_SESSION['uniq'])) {
    header("Location: log.php");
}else{
  $user_id = $_SESSION['uniq']?? 0;
  $select = mysqli_query($conn, "SELECT * FROM users WHERE unique_id = '$user_id'");
  
  if($select->num_rows > 0){

    $data = mysqli_fetch_array( $select);
    $name = $data['name'];
    $email = $data['mail'];
    $role = $data['role'];


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
    
    <title>Dashboard-passcloud</title>
    
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    
    <link rel="stylesheet" href="assets/dash.css?v=<?php echo time(); ?>">
</head>
<body>
  <header>
    <div class="logo">
      <i class="fas fa-cloud"></i>
      PassCloud
    </div>
    
    <div class="user-menu">
      <button class="user-btn" id="userBtn">
        <span><?php
// Display only the first letter of username in uppercase
$first_letter = strtoupper(substr($name, 0, 1));
echo $first_letter;
?></span>
      </button>
     
<div class="user-dropdown" id="userDropdown">
    <a href="index.php"><i class="fas fa-home"></i> Home</a>
    <a href="share_dashboard.php"><i class="fas fa-share-alt"></i> Password Sharing</a>
    <a href="usersecurity.php"><i class="fas fa-shield-alt"></i> Security Settings</a>
    <a href="accouts.php"><i class="fas fa-user-cog"></i> Account Settings</a>
    <a href="dl.php"><i class="fas fa-download"></i>Download App</a>
    <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
    <?php if (isset($_SESSION['uniq'])): 
    if($role == "admin" || $role !== "user"){
     echo' <a href="admin.php"><i class="fas fa-administrator"></i>back to admin</a>';
    }?>
      <?php endif  ?>
</div>
    </div>
  </header>

  <div class="content">
    <div class="welcome-section">
      <h2>Welcome,<?php
// Display first name with proper capitalization
$first_name = ucfirst(strtolower(explode(' ', $name)[0]));
echo $first_name;
?>! 👋</h2>
      <p>Manage your passwords securely and efficiently with PassCloud. Everything you need is right here.</p>
    </div>
    </div>
    

   <div class="cards">
    <div class="card">
        <div class="card-icon">
            <i class="fas fa-key"></i>
        </div>
        <h3>Password Vault</h3>
        <p>Access and manage all your saved passwords in one secure, encrypted vault.</p>
        <a href="vault.php" class="btn">Open Vault</a>
    </div>

    <div class="card">
        <div class="card-icon">
            <i class="fas fa-bolt"></i>
        </div>
        <h3>Password Generator</h3>
        <p>Create strong, unique passwords instantly to secure your online accounts.</p>
        <a href="passgen.php" class="btn">Generate</a>
    </div>

    <div class="card">
        <div class="card-icon">
            <i class="fas fa-share-alt"></i>
        </div>
        <!-- Add notification bell to dashboard header -->
<div class="notification-bell" id="notificationBell" style="margin-left: auto; margin-right: 15px;">
    <i class="fas fa-bell"></i>
    <span class="notification-badge" id="liveNotificationCount">0</span>
</div>
        <h3>Share Passwords</h3>
        <p>Securely share passwords with team members or family with controlled access.</p>
        <a href="share_dashboard.php" class="btn">Share Passwords</a>
    </div>

    <div class="card">
        <div class="card-icon">
            <i class="fas fa-sync-alt"></i>
        </div>
        <h3>Sync Across Devices</h3>
        <p>Access your password vault from any device - desktop, tablet, or mobile.</p>
        <a href="count.php" class="btn">Sync Now</a>
    </div>

    <div class="card">
        <div class="card-icon">
            <i class="fas fa-shield-alt"></i>
        </div>
        <h3>Security Audit</h3>
        <p>Check your password strength and get recommendations for improvement.</p>
        <a href="usersecurity.php" class="btn">Check Security</a>
    </div>

    <div class="card">
        <div class="card-icon">
            <i class="fas fa-cogs"></i>
        </div>
        <h3>Security Settings</h3>
        <p>Advanced security controls and monitoring for your account.</p>
        <a href="accouts.php" class="btn">Settings</a>
    </div>
</div>
</div>

  <footer>
    &copy; <?php echo date("Y"); ?> PassCloud — Secure Your Digital Life
  </footer>
<script src="assets/dash.js?v=<?php echo time(); ?>"></script>
 <script nonce="<?php echo CSP_NONCE; ?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
    </script>
</body>
</html>