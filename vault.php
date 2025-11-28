  <?php
  require_once 'db.php';
  require_once 'security.php';
  session_start();
  if (!isset($_SESSION['uniq'])) {
      header("Location: log.php");
      exit;
  } else{
    $user_id = $_SESSION['uniq']?? 0;
    $select = mysqli_query($conn, "SELECT * FROM users WHERE unique_id = '$user_id'");
    
    if($select->num_rows > 0){

      $data = mysqli_fetch_array( $select);
      $name = $data['name'];
      $email = $data['mail'];
      $uniq = $data['unique_id'];


    }
  }

  // Add new entry
  if (isset($_POST['add'])) {
      $site = htmlspecialchars($_POST['site']);
      $mail = htmlspecialchars($_POST["mail"]);
      $password = htmlspecialchars($_POST['password']);

      $insert = $conn->prepare("INSERT INTO vault (unique_id, site, mail, pass) VALUES (?, ?, ?, ?)");
      $insert->bind_param("ssss", $user_id, $site, $mail, $password);
      if ($insert->execute()) {
          $add = 'Password saved successfully!';
      }
      $insert->close();
  }

  // Fetch user entries
  $entries = $conn->prepare("SELECT * FROM vault WHERE unique_id = ?");
  $entries->bind_param("s", $user_id);
  $entries->execute();
  $data = $entries->get_result(); 
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
      
      <title>Secure vault-passcloud</title>
      
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
            integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
            crossorigin="anonymous" 
            referrerpolicy="no-referrer">
      
      <link rel="stylesheet" href="assets/vault.css?v=<?php echo time(); ?>">
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
        <h1>Password Vault</h1>
        <p>Manage and secure your passwords in one place</p>
      </div>

      <div class="add-form">
        <h2><i class="fas fa-plus-circle"></i> Add New Password</h2>
        <!-- Add this in vault.php after the add password form -->
  <div style="text-align: center; margin: 20px 0;">
      <a href="share_dashboard.php" class="btn" style="background: var(--accent);">
          <i class="fas fa-share-alt"></i> Share Passwords
      </a>
  </div>
        
        <?php if(isset($add)): ?>
          <div class="success-message">
            <i class="fas fa-check-circle"></i>
            <?php echo $add ?>
          </div>
        <?php endif; ?>
        
      <form method="POST" action="">
          <input type="hidden" name="csrf_token" value="<?php echo CSRF_TOKEN; ?>">
          <div class="form-grid">
            <div class="form-group">
              <label for="site">Website / App</label>
              <input type="text" id="site" name="site" class="form-control" placeholder="e.g. google.com" required>
            </div>
            
            <div class="form-group">
              <label for="mail">Username / Email</label>
              <input type="email" id="mail" name="mail" class="form-control" placeholder="your@email.com" required>
            </div>
            
            <div class="form-group">
              <label for="password">Password</label>
              <input type="password" id="password" name="password" class="form-control" placeholder="Enter password" required>
            </div>
          </div>
          
          <button type="submit" name="add" class="btn btn-block">
            <i class="fas fa-save"></i> Save Password
          </button>
        </form>
      </div>

      <div class="table-section">
        <h2><i class="fas fa-key"></i> Your Saved Passwords</h2>
        
        <div class="table-wrapper">
          <?php if($data->num_rows > 0): ?>
            <table>
              <thead>
                <tr>
                  <th>Site</th>
                  <th>Username/Email</th>
                  <th>Password</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <?php while ($row = $data->fetch_assoc()) { 
                  $rowKey = htmlspecialchars($row['site'] . '|' . $row['pass']);
                ?>
                <tr data-key="<?= $rowKey ?>">
                  <td data-label="Site"><?= htmlspecialchars($row['site']) ?></td>
                  <td data-label="Username/Email"><?= htmlspecialchars($row['mail']) ?></td>
                  <td data-label="Password">
                    <span class="pwd" data-password="<?= htmlspecialchars($row['pass']) ?>">•••••••</span>
                  </td>
                  <td data-label="Actions">
                    <div class="action-buttons">
                      <button class="action-btn copy-btn" onclick="copyCell(this)" title="Copy Password">
                        <i class="fas fa-copy"></i>
                      </button>
                      <button class="action-btn view-btn" onclick="togglePwd(this)" title="Show/Hide Password">
                        <i class="fas fa-eye"></i>
                      </button>
                      <button class="action-btn delete-btn" onclick="hideRow(this)" title="Delete">
                        <i class="fas fa-trash"></i>
                      </button>
                    </div>
                  </td>
                </tr>
                <?php } ?>
              </tbody>
            </table>
          <?php else: ?>
            <div class="empty-state">
              <i class="fas fa-key"></i>
              <h3>No passwords saved yet</h3>
              <p>Add your first password using the form above</p>
            </div>
          <?php endif; ?>
        </div>
      </div>
    </div>
    <div class="bookspace"><a href="file.php" class="btn btn-block">upload your credentials to passcloud </a></div>
    <div class="security-tip">
        <i class="fas fa-shield-alt"></i>
        <small>Security Tip: Avoid using the same password for different websites and social media accounts!</small>
      </div>

    <footer>
      <p>&copy; <?php echo date("Y"); ?> PassCloud — Secure Your Digital Life</p>
    </footer>

    <script src="assets/vault.js?v=<?php echo time(); ?>">
      
      </script>
  </body>
  </html>










