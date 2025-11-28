<?php
require_once 'db.php';
require_once 'security.php';
session_start();
if (!isset($_SESSION['uniq'])) {
    header("Location: log.php");
    exit;
}
require_once 'security.php';


$user_id = $_SESSION['uniq'] ?? 0;
$select = mysqli_query($conn, "SELECT * FROM users WHERE unique_id = '$user_id'");
if($select->num_rows > 0) {
    $data = mysqli_fetch_array($select);
    $name = $data['name'];
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
    
    <title>Password Generator - PassCloud</title>
    
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    
    <link rel="stylesheet" href="assets/passgen.css?v=<?php echo time(); ?>">
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
        <div class="card">
            <div class="card-header">
                <h1><i class="fas fa-key"></i> Password Generator</h1>
                <p>Create strong, unique passwords instantly</p>
            </div>

            <div class="form-group">
                <label for="length">Password Length: <span id="lenVal" class="length-value">16</span></label>
                <div class="slider-container">
                    <input id="length" type="range" min="6" max="64" value="16" />
                </div>
            </div>

            <div class="form-group">
                <label>Character Types:</label>
                <div class="options-grid">
                    <div class="option-item">
                        <input id="lower" type="checkbox" checked />
                        <label for="lower">Lowercase (a-z)</label>
                    </div>
                    <div class="option-item">
                        <input id="upper" type="checkbox" checked />
                        <label for="upper">Uppercase (A-Z)</label>
                    </div>
                    <div class="option-item">
                        <input id="numbers" type="checkbox" checked />
                        <label for="numbers">Numbers (0-9)</label>
                    </div>
                    <div class="option-item">
                        <input id="symbols" type="checkbox" />
                        <label for="symbols">Symbols (!@#$)</label>
                    </div>
                </div>
            </div>

            <div class="form-group">
                <label>Generated Password:</label>
                <div class="output-container">
                    <input id="password" class="password-display" readonly aria-label="Generated password" />
                    <button id="copy" class="btn btn-secondary" title="Copy to clipboard">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
            </div>

            <div class="strength-meter">
                <div class="strength-bar">
                    <div id="bar" class="strength-fill"></div>
                </div>
                <div class="strength-info">
                    <div id="strengthText">Strength: —</div>
                    <div id="entropy">Entropy: — bits</div>
                </div>
            </div>

            <div class="action-buttons">
                <button id="gen" class="btn btn-primary">
                    <i class="fas fa-sync-alt"></i> Generate New
                </button>
                <button id="regen" class="btn btn-secondary">
                    <i class="fas fa-redo"></i> Regenerate
                </button>
            </div>

            <div class="tip-box">
                <i class="fas fa-lightbulb"></i>
                <div>Tip: Use the generated password in your vault or directly on websites by copying and pasting.</div>
            </div>
        </div>
    </div>

    <footer>
        <p>&copy; <?php echo date("Y"); ?> PassCloud — Secure Your Digital Life</p>
    </footer>
    <script src="assets/passgen.js?v=<?php echo time(); ?>"></script>
     <script nonce="<?php echo CSP_NONCE; ?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
    </script>
</body>
</html>