<?php
require_once 'db.php';
require_once 'security.php';
session_start();
if(isset($_SESSION['uniq'])) {
  $user_id = $_SESSION['uniq']?? 0;
  $select = mysqli_query($conn, "SELECT * FROM users WHERE unique_id = '$user_id'");
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
    
    <title>PassCloud - Home</title>
    
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    
    <link rel="stylesheet" href="assets/index.css?v=<?php echo time(); ?>">
</head>
<body>
    <!-- Header -->
    <header>
        <div class="container">
            <nav class="navbar">
                <div class="logo">
                    <i class="fas fa-cloud"></i>
                    PassCloud
                </div>
            </nav>
        </div>
    </header>

    <!-- Hero Section -->
    <section class="hero">
        <div class="container">
            <h1>Secure Your Digital Life</h1>
            <p>PassCloud helps you manage, generate, and store your passwords safely in one place. Access your vault anywhere, anytime.</p>
            <div class="hero-buttons">
                <?php if (!isset($_SESSION['uniq'])): ?>
                <a href="signup.php" class="btn btn-primary">Get Started</a>
                <a href="log.php" class="btn btn-secondary">Login</a>
                <?php endif; ?>
                <button onclick="openmore()" class="btn btn-primary">Learn More</button>
                <div class="nav-buttons">
                    <a href="dl.php" class="btn btn-secondary">Download App</a>
                    <?php if (isset($_SESSION['uniq'])): ?>
                    <a href="dashboard.php" class="btn btn-primary">Dashboard</a>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </section>
    
    <!-- Learn More Section (Initially Hidden) -->
    <div id="more">
        <div class="learn-more-content">
            <button onclick="closemore()" class="close-learn-more">
                <i class="fas fa-arrow-left"></i> Back to Main Content
            </button>
            
            <!-- Learn More Content -->
            <section class="learn-hero">
                <h1>Learn More About PassCloud</h1>
                <p>Your complete guide to understanding how PassCloud protects your digital life while making password management effortless and secure.</p>
            </section>

            <!-- Problem & Solution Section -->
            <section class="learn-section">
                <div class="problem-solution">
                    <div class="problem-box">
                        <h3><i class="fas fa-exclamation-triangle"></i> The Digital Problem</h3>
                        <p>The average person struggles with password overload, security risks, and time wasted on account management.</p>
                        <div class="stats">
                            <div class="stat-item">
                                <div class="stat-value">100+</div>
                                <div class="stat-label">Online Accounts</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value">65%</div>
                                <div class="stat-label">Reuse Passwords</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value">20+</div>
                                <div class="stat-label">Hours Wasted Yearly</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value">80%</div>
                                <div class="stat-label">Higher Breach Risk</div>
                            </div>
                        </div>
                    </div>
                    <div class="solution-box">
                        <h3><i class="fas fa-shield-alt"></i> Our Solution</h3>
                        <p>PassCloud provides a secure, intuitive platform that simplifies digital security for everyone.</p>
                        <div class="stats">
                            <div class="stat-item">
                                <div class="stat-value">1</div>
                                <div class="stat-label">Master Password</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value">100%</div>
                                <div class="stat-label">Encrypted</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value">24/7</div>
                                <div class="stat-label">Access & Protection</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value">0</div>
                                <div class="stat-label">Knowledge of Your Data</div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Features Section -->
            <section class="learn-section">
                <div class="section-title">
                    <h2>How PassCloud Works</h2>
                    <p>Advanced technology made simple for complete peace of mind</p>
                </div>
                <div class="features-grid-learn">
                    <div class="feature-card-learn">
                        <div class="feature-icon">
                            <i class="fas fa-lock"></i>
                        </div>
                        <h3>Military-Grade Encryption</h3>
                        <p>Your data is protected with AES-256 bit encryption, the same standard used by governments and financial institutions worldwide.</p>
                    </div>
                    <div class="feature-card-learn">
                        <div class="feature-icon">
                            <i class="fas fa-key"></i>
                        </div>
                        <h3>Zero-Knowledge Architecture</h3>
                        <p>We never have access to your passwords or encryption keys. Your data remains private, even from us.</p>
                    </div>
                    <div class="feature-card-learn">
                        <div class="feature-icon">
                            <i class="fas fa-sync-alt"></i>
                        </div>
                        <h3>Cross-Platform Sync</h3>
                        <p>Access your passwords seamlessly across all your devices with secure, encrypted synchronization.</p>
                    </div>
                    <div class="feature-card-learn">
                        <div class="feature-icon">
                            <i class="fas fa-user-shield"></i>
                        </div>
                        <h3>Advanced Security Features</h3>
                        <p>Two-factor authentication, breach monitoring, and security alerts keep your accounts protected.</p>
                    </div>
                </div>
            </section>

            <!-- Technology Section -->
            <section class="learn-section">
                <div class="section-title">
                    <h2>Our Security Technology</h2>
                    <p>Built on a foundation of trust and transparency</p>
                </div>
                <div class="tech-stack-learn">
                    <div class="tech-item-learn">
                        <div class="tech-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <h3>End-to-End Encryption</h3>
                        <p>Your data is encrypted before it leaves your device</p>
                    </div>
                    <div class="tech-item-learn">
                        <div class="tech-icon">
                            <i class="fas fa-cloud"></i>
                        </div>
                        <h3>Secure Cloud Storage</h3>
                        <p>Redundant, encrypted storage with 99.9% uptime</p>
                    </div>
                    <div class="tech-item-learn">
                        <div class="tech-icon">
                            <i class="fas fa-user-lock"></i>
                        </div>
                        <h3>Zero-Knowledge Proof</h3>
                        <p>We cannot access or read your encrypted data</p>
                    </div>
                    <div class="tech-item-learn">
                        <div class="tech-icon">
                            <i class="fas fa-audit"></i>
                        </div>
                        <h3>Regular Security Audits</h3>
                        <p>Third-party testing to ensure maximum protection</p>
                    </div>
                </div>
            </section>

            <!-- Comparison Section -->
            <section class="learn-section">
                <div class="section-title">
                    <h2>Why Choose PassCloud?</h2>
                    <p>See how we stack up against the competition</p>
                </div>
                <div class="comparison-learn">
                    <div class="comparison-header-learn">
                        <div>Features</div>
                        <div>PassCloud</div>
                        <div>Other Managers</div>
                    </div>
                    <div class="comparison-row-learn">
                        <div>Zero-Knowledge Architecture</div>
                        <div class="check"><i class="fas fa-check-circle"></i></div>
                        <div class="cross"><i class="fas fa-times-circle"></i></div>
                    </div>
                    <div class="comparison-row-learn">
                        <div>Free Plan with Essential Features</div>
                        <div class="check"><i class="fas fa-check-circle"></i></div>
                        <div class="cross"><i class="fas fa-times-circle"></i></div>
                    </div>
                    <div class="comparison-row-learn">
                        <div>Cross-Platform Sync</div>
                        <div class="check"><i class="fas fa-check-circle"></i></div>
                        <div class="check"><i class="fas fa-check-circle"></i></div>
                    </div>
                    <div class="comparison-row-learn">
                        <div>Advanced Sharing Options</div>
                        <div class="check"><i class="fas fa-check-circle"></i></div>
                        <div class="cross"><i class="fas fa-times-circle"></i></div>
                    </div>
                </div>
            </section>
        </div>
    </div>

    <!-- Features Section -->
    <section class="features">
        <div class="container">
            <div class="section-title">
                <h2>Why Choose PassCloud?</h2>
                <p>Discover the features that make PassCloud the best password manager for you</p>
            </div>
            <div class="features-grid">
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <h3>Strong Security</h3>
                    <p>Protect your accounts with strong password storage and encryption.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-bolt"></i>
                    </div>
                    <h3>Fast Access</h3>
                    <p>Log in quickly and access your saved credentials anywhere.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-key"></i>
                    </div>
                    <h3>Password Generator</h3>
                    <p>Create strong, unique passwords with one click.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-laptop"></i>
                    </div>
                    <h3>Cross-Platform</h3>
                    <p>Access your password vault from desktop or mobile devices.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- CTA Section -->
    <?php if (!isset($_SESSION['uniq'])): ?>
    <section class="cta">
        <div class="container">
            <h2>Ready to Secure Your Digital Life?</h2>
            <p>Join millions of users who trust PassCloud with their passwords and digital security.</p>
            <a href="signup.php" class="btn btn-primary">Get Started Now</a>
        </div>
    </section>
    <?php endif; ?>

    <!-- Footer -->
    <footer>
        <div class="container">
            <div class="footer-content">
                <div class="footer-column">
                    <h3>PassCloud</h3>
                    <p>Secure password management for everyone. Access your passwords anywhere, anytime.</p>
                </div>
                <div class="footer-column">
                    <h3>Product</h3>
                    <ul>
                        <li><a href="#">Features</a></li>
                        <li><a href="#">Pricing</a></li>
                        <li><a href="dl.php">Download</a></li>
                        <li><a href="#">Security</a></li>
                    </ul>
                </div>
                <div class="footer-column">
                    <h3>Company</h3>
                    <ul>
                        <li><a href="#">About Us</a></li>
                        <li><a href="#">Careers</a></li>
                        <li><a href="#">Blog</a></li>
                        <li><a href="#">Press</a></li>
                    </ul>
                </div>
                <div class="footer-column">
                    <h3>Support</h3>
                    <ul>
                        <li><a href="#">Help Center</a></li>
                        <li><a href="#">Contact Us</a></li>
                        <li><a href="#">Privacy Policy</a></li>
                        <li><a href="#">Terms of Service</a></li>
                    </ul>
                </div>
            </div>
            <div class="copyright">
                <p>&copy; 2025 PassCloud. All rights reserved.</p>
            </div>
        </div>
    </footer>

    <script nonce="<?php echo CSP_NONCE; ?>">
        const moreSection = document.getElementById('more');
        
        function openmore() {
            moreSection.style.display = 'block';
            // Smooth scroll to the learn more section
            moreSection.scrollIntoView({ behavior: 'smooth' });
        }
        
        function closemore() {
            moreSection.style.display = 'none';
            // Scroll back to top
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
    </script>
</body>
</html>