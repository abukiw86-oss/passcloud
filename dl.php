<?php
require_once "db.php";
require_once 'security.php';
session_start();
// Optional: Check if user is logged in to show personalized message
$user_id = $_SESSION['uniq']?? 0;
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
    
    <title>download App - PassCloud</title>
    
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    
    <link rel="stylesheet" href="assets/dl.css?v=<?php echo time(); ?>">
</head>
<body>
    <header>
        <div class="logo">
            <i class="fas fa-cloud"></i>
            PassCloud
        </div>
       <?php if (isset($_SESSION['uniq'])): ?>
        <a href="dashboard.php" class="back-btn">
            <i class="fas fa-arrow-left"></i>
            <span>Back to Dashboard</span>
        </a>
        <?php endif; ?>
        <?php if (!isset($_SESSION['uniq'])): ?>
        <a href="index.php" class="back-btn">
            <i class="fas fa-arrow-left"></i>
            <span>Back to home</span>
        </a>
        <?php endif; ?>
    </header>

    <div class="container">
        <div class="download-card">
            <div class="app-icon pulse">
                <i class="fas fa-cloud"></i>
            </div>
            
            <h1>Get PassCloud Mobile</h1>
            <p>Take your passwords everywhere. Access your vault securely from your Android device with our native mobile app.</p>
            
            <a href="passcloud.apk" download class="download-btn">
                <i class="fas fa-download"></i>
                Download for Android
            </a>

            <div class="security-badge">
                <i class="fas fa-shield-alt"></i>
                Secure & Verified
            </div>

            <div class="features">
                <div class="feature">
                    <div class="feature-icon">
                        <i class="fas fa-sync-alt"></i>
                    </div>
                    <div class="feature-text">
                        <h3>Sync Across Devices</h3>
                        <p>Access passwords on all your devices</p>
                    </div>
                </div>
                
                <div class="feature">
                    <div class="feature-icon">
                        <i class="fas fa-fingerprint"></i>
                    </div>
                    <div class="feature-text">
                        <h3>Biometric Login</h3>
                        <p>Secure access with fingerprint</p>
                    </div>
                </div>
                
                <div class="feature">
                    <div class="feature-icon">
                        <i class="fas fa-bolt"></i>
                    </div>
                    <div class="feature-text">
                        <h3>Fast & Lightweight</h3>
                        <p>Optimized for mobile performance</p>
                    </div>
                </div>
                
                <div class="feature">
                    <div class="feature-icon">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <div class="feature-text">
                        <h3>End-to-End Encrypted</h3>
                        <p>Your data stays private</p>
                    </div>
                </div>
            </div>

            <div class="app-info">
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Version</span>
                        <span class="info-value">1.0.0</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Size</span>
                        <span class="info-value">~15 MB</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Requires</span>
                        <span class="info-value">Android 8.0+</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Updated</span>
                        <span class="info-value"><?php echo date('M j, Y'); ?></span>
                    </div>
                </div>
            </div>

            <div style="margin-top: 30px; font-size: 0.9rem; color: rgba(255, 255, 255, 0.6);">
                <p><i class="fas fa-info-circle"></i> After installation, you may need to allow installation from unknown sources</p>
            </div>
        </div>
    </div>

    <footer>
        <p>&copy; <?php echo date("Y"); ?> PassCloud — Secure Your Digital Life</p>
    </footer>

<script src="assets/dl.js?v=<?php echo time(); ?>"></script>
 <script nonce="<?php echo CSP_NONCE; ?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
    </script>
</body>
</html>