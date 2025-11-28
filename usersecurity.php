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
}

// Get user's passwords for analysis
$passwords_result = mysqli_query($conn, "SELECT * FROM vault WHERE unique_id = '$user_id'");
$total_passwords = $passwords_result->num_rows;

// Analyze password strength
$weak_passwords = 0;
$medium_passwords = 0;
$strong_passwords = 0;
$reused_passwords = 0;
$old_passwords = 0;

$password_analysis = [];
$password_frequency = [];

while($row = $passwords_result->fetch_assoc()) {
    $password = $row['pass'];
    $site = $row['site'];
    $created_at = $row['date'];
    
    // Analyze password strength
    $strength = analyzePasswordStrength($password);
    $password_analysis[] = [
        'site' => $site,
        'password' => $password,
        'strength' => $strength['level'],
        'score' => $strength['score'],
        'feedback' => $strength['feedback'],
        'created_at' => $created_at
    ];
    
    // Count strength levels
    if ($strength['level'] === 'weak') $weak_passwords++;
    elseif ($strength['level'] === 'medium') $medium_passwords++;
    else $strong_passwords++;
    
    // Check for reused passwords
    if (isset($password_frequency[$password])) {
        $password_frequency[$password]++;
        $reused_passwords++;
    } else {
        $password_frequency[$password] = 1;
    }
    
    // Check for old passwords (older than 90 days)
    $password_age = time() - strtotime($created_at);
    if ($password_age > 90 * 24 * 60 * 60) {
        $old_passwords++;
    }
}

// Calculate security score (0-100)
$security_score = 0;
if ($total_passwords > 0) {
    $strength_score = ($strong_passwords / $total_passwords) * 40;
    $uniqueness_score = (($total_passwords - $reused_passwords) / $total_passwords) * 30;
    $freshness_score = (($total_passwords - $old_passwords) / $total_passwords) * 30;
    $security_score = min(100, $strength_score + $uniqueness_score + $freshness_score);
}

// Password strength analysis function
function analyzePasswordStrength($password) {
    $score = 0;
    $feedback = [];
    
    // Length check
    $length = strlen($password);
    if ($length >= 12) $score += 3;
    elseif ($length >= 8) $score += 2;
    elseif ($length >= 6) $score += 1;
    else $feedback[] = "Password is too short (minimum 6 characters)";
    
    // Lowercase letters
    if (preg_match('/[a-z]/', $password)) $score += 1;
    else $feedback[] = "Add lowercase letters";
    
    // Uppercase letters
    if (preg_match('/[A-Z]/', $password)) $score += 1;
    else $feedback[] = "Add uppercase letters";
    
    // Numbers
    if (preg_match('/[0-9]/', $password)) $score += 1;
    else $feedback[] = "Add numbers";
    
    // Special characters
    if (preg_match('/[^A-Za-z0-9]/', $password)) $score += 2;
    else $feedback[] = "Add special characters";
    
    // Common patterns check
    $common_patterns = ['123456', 'password', 'qwerty', 'admin', 'welcome'];
    foreach ($common_patterns as $pattern) {
        if (stripos($password, $pattern) !== false) {
            $score -= 2;
            $feedback[] = "Avoid common patterns like '$pattern'";
            break;
        }
    }
    
    // Determine strength level
    if ($score >= 7) {
        $level = 'strong';
    } elseif ($score >= 4) {
        $level = 'medium';
    } else {
        $level = 'weak';
    }
    
    return [
        'score' => $score,
        'level' => $level,
        'feedback' => $feedback
    ];
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
    
    <title>Your Status - PassCloud</title>
    
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    
    <link rel="stylesheet" href="assets/scure.css?v=<?php echo time(); ?>">
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
            <h1><i class="fas fa-shield-alt"></i> Security Audit</h1>
            <p>Check your password strength and get recommendations for improvement</p>
        </div>

        <!-- Security Score -->
        <div class="security-score">
            <div class="score-circle" style="--score-percent: <?php echo $security_score; ?>">
                <div class="score-value"><?php echo round($security_score); ?></div>
            </div>
            <div class="score-label">Overall Security Score</div>
        </div>

        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon weak">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <div class="stat-number"><?php echo $weak_passwords; ?></div>
                <div class="stat-label">Weak Passwords</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon medium">
                    <i class="fas fa-minus-circle"></i>
                </div>
                <div class="stat-number"><?php echo $medium_passwords; ?></div>
                <div class="stat-label">Medium Passwords</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon strong">
                    <i class="fas fa-check-circle"></i>
                </div>
                <div class="stat-number"><?php echo $strong_passwords; ?></div>
                <div class="stat-label">Strong Passwords</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon reused">
                    <i class="fas fa-copy"></i>
                </div>
                <div class="stat-number"><?php echo $reused_passwords; ?></div>
                <div class="stat-label">Reused Passwords</div>
            </div>
        </div>

        <!-- Password Analysis -->
        <div class="analysis-section">
            <div class="section-header">
                <i class="fas fa-key"></i>
                <h2>Password Strength Analysis</h2>
            </div>

            <div class="password-list">
                <?php if($total_passwords > 0): ?>
                    <?php foreach($password_analysis as $analysis): ?>
                        <div class="password-item">
                            <div class="password-info">
                                <span class="strength-badge <?php echo $analysis['strength']; ?>">
                                    <?php echo ucfirst($analysis['strength']); ?>
                                </span>
                                <div class="password-details">
                                    <h4><?php echo htmlspecialchars($analysis['site']); ?></h4>
                                    <div class="password-meta">
                                        Score: <?php echo $analysis['score']; ?>/8 • 
                                        Created: <?php echo date('M j, Y', strtotime($analysis['created_at'])); ?>
                                    </div>
                                    <?php if(!empty($analysis['feedback'])): ?>
                                        <div class="password-feedback">
                                            <strong>Improve:</strong> <?php echo implode(', ', $analysis['feedback']); ?>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <a href="vault.php" class="btn btn-primary">
                                <i class="fas fa-edit"></i> Update
                            </a>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <div class="empty-state">
                        <i class="fas fa-key"></i>
                        <h3>No passwords found</h3>
                        <p>Start by adding passwords to your vault to get security recommendations</p>
                        <a href="vault.php" class="btn btn-primary" style="margin-top: 20px;">
                            <i class="fas fa-plus"></i> Add Passwords
                        </a>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Security Recommendations -->
        <div class="analysis-section">
            <div class="section-header">
                <i class="fas fa-lightbulb"></i>
                <h2>Security Recommendations</h2>
            </div>

            <div class="recommendations-list">
                <?php if($total_passwords === 0): ?>
                    <div class="recommendation-item critical">
                        <i class="fas fa-exclamation-circle recommendation-icon"></i>
                        <div class="recommendation-content">
                            <h4>Add Passwords to Your Vault</h4>
                            <p>Start securing your accounts by adding passwords to your PassCloud vault.</p>
                        </div>
                    </div>
                <?php else: ?>
                    <?php if($weak_passwords > 0): ?>
                        <div class="recommendation-item critical">
                            <i class="fas fa-exclamation-circle recommendation-icon"></i>
                            <div class="recommendation-content">
                                <h4>Strengthen Weak Passwords</h4>
                                <p>You have <?php echo $weak_passwords; ?> weak password(s). Update them to improve your security.</p>
                            </div>
                        </div>
                    <?php endif; ?>

                    <?php if($reused_passwords > 0): ?>
                        <div class="recommendation-item critical">
                            <i class="fas fa-exclamation-circle recommendation-icon"></i>
                            <div class="recommendation-content">
                                <h4>Stop Reusing Passwords</h4>
                                <p>You're reusing passwords across <?php echo $reused_passwords; ?> account(s). Use unique passwords for each site.</p>
                            </div>
                        </div>
                    <?php endif; ?>

                    <?php if($old_passwords > 0): ?>
                        <div class="recommendation-item warning">
                            <i class="fas fa-clock recommendation-icon"></i>
                            <div class="recommendation-content">
                                <h4>Update Old Passwords</h4>
                                <p>You have <?php echo $old_passwords; ?> password(s) older than 90 days. Consider rotating them.</p>
                            </div>
                        </div>
                    <?php endif; ?>

                    <?php if($security_score >= 80): ?>
                        <div class="recommendation-item">
                            <i class="fas fa-check-circle recommendation-icon"></i>
                            <div class="recommendation-content">
                                <h4>Excellent Security Habits</h4>
                                <p>Your password security is strong! Keep up the good work and continue monitoring your passwords regularly.</p>
                            </div>
                        </div>
                    <?php elseif($security_score >= 60): ?>
                        <div class="recommendation-item">
                            <i class="fas fa-info-circle recommendation-icon"></i>
                            <div class="recommendation-content">
                                <h4>Good Security Foundation</h4>
                                <p>Your security is decent, but there's room for improvement. Focus on strengthening weak passwords.</p>
                            </div>
                        </div>
                    <?php else: ?>
                        <div class="recommendation-item warning">
                            <i class="fas fa-exclamation-triangle recommendation-icon"></i>
                            <div class="recommendation-content">
                                <h4>Immediate Action Required</h4>
                                <p>Your password security needs significant improvement. Focus on weak and reused passwords first.</p>
                            </div>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>

                <div class="recommendation-item">
                    <i class="fas fa-sync-alt recommendation-icon"></i>
                    <div class="recommendation-content">
                        <h4>Regular Security Audits</h4>
                        <p>Perform security audits monthly to ensure your passwords remain secure over time.</p>
                    </div>
                </div>

                <div class="recommendation-item">
                    <i class="fas fa-bolt recommendation-icon"></i>
                    <div class="recommendation-content">
                        <h4>Use Password Generator</h4>
                        <p>Generate strong, unique passwords for new accounts using our password generator tool.</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Action Buttons -->
        <div style="text-align: center; margin-top: 40px;">
            <a href="passgen.php" class="btn btn-primary" style="margin-right: 15px;">
                <i class="fas fa-bolt"></i> Generate Strong Passwords
            </a>
            <a href="vault.php" class="btn" style="background: rgba(255, 255, 255, 0.1); color: white; border: 1px solid rgba(255, 255, 255, 0.2);">
                <i class="fas fa-edit"></i> Update Passwords
            </a>
        </div>
    </div>

    <footer>
        <p>&copy; <?php echo date("Y"); ?> PassCloud — Secure Your Digital Life</p>
    </footer>
    <script src="assets/secure.js?v=<?php echo time(); ?>"></script>
     <script nonce="<?php echo CSP_NONCE; ?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
    </script>
</body>
</html>