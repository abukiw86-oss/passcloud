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
    $current_name = $data['name'];
    $current_email = $data['mail'];
}

$success = '';
$error = '';
$show_security_questions = false;

// Get current security questions if they exist
$security_questions = mysqli_query($conn, "SELECT * FROM security_questions WHERE unique_id = '$user_id'");
$has_security_questions = $security_questions->num_rows > 0;
$current_questions = $has_security_questions ? $security_questions->fetch_assoc() : null;

// Predefined security questions
$predefined_questions = [
    "What was your favorite food as a child?",
    "What is your favorite clothing brand?",
    "What was your first pet's name?",
    "What is your mother's maiden name?",
    "What city were you born in?",
    "What is your favorite movie?",
    "What was your first car?",
    "What is your favorite book?",
    "What is your favorite sports team?",
    "What is your best friend's nickname?",
    "What is your favorite color?",
    "What is your father's middle name?",
    "What is your favorite holiday destination?",
    "What is your favorite type of cuisine?",
    "What is your favorite type of music?"
];

// Verify password to show security questions
if (isset($_POST['verify_password'])) {
    $current_password = $_POST['current_password'];
    
    if (password_verify($current_password, $data['pass'])) {
        $show_security_questions = true;
        $success = "Password verified! You can now update your security questions.";
    } else {
        $error = "Current password is incorrect!";
    }
}

// Update Name
if (isset($_POST['update_name'])) {
    $new_name = htmlspecialchars(trim($_POST['name']));
    
    if (empty($new_name)) {
        $error = "Name cannot be empty!";
    } elseif (strlen($new_name) < 2) {
        $error = "Name must be at least 2 characters long!";
    } else {
        $update = $conn->prepare("UPDATE users SET name = ? WHERE unique_id = ?");
        $update->bind_param("ss", $new_name, $user_id);
        
        if ($update->execute()) {
            $success = "Name updated successfully!";
            $name = $new_name;
            $current_name = $new_name;
        } else {
            $error = "Failed to update name. Please try again.";
        }
        $update->close();
    }
}

// Update Email
if (isset($_POST['update_email'])) {
    $new_email = htmlspecialchars(trim($_POST['email']));
    
    if (empty($new_email)) {
        $error = "Email cannot be empty!";
    } elseif (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
        $error = "Please enter a valid email address!";
    } else {
        // Check if email already exists
        $check = $conn->prepare("SELECT id FROM users WHERE mail = ? AND unique_id != ?");
        $check->bind_param("ss", $new_email, $user_id);
        $check->execute();
        $check->store_result();
        
        if ($check->num_rows > 0) {
            $error = "This email is already registered!";
        } else {
            $update = $conn->prepare("UPDATE users SET mail = ? WHERE unique_id = ?");
            $update->bind_param("ss", $new_email, $user_id);
            
            if ($update->execute()) {
                $success = "Email updated successfully!";
                $email = $new_email;
                $current_email = $new_email;
            } else {
                $error = "Failed to update email. Please try again.";
            }
            $update->close();
        }
        $check->close();
    }
}

// Update Password
if (isset($_POST['update_password'])) {
    $current_password = $_POST['current_password_pass'];
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];
    
    if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
        $error = "All password fields are required!";
    } elseif (!password_verify($current_password, $data['pass'])) {
        $error = "Current password is incorrect!";
    } elseif ($new_password !== $confirm_password) {
        $error = "New passwords do not match!";
    } elseif (strlen($new_password) < 6) {
        $error = "Password must be at least 6 characters long!";
    } else {
        $new_hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
        $update = $conn->prepare("UPDATE users SET pass = ? WHERE unique_id = ?");
        $update->bind_param("ss", $new_hashed_password, $user_id);
        
        if ($update->execute()) {
            $success = "Password updated successfully!";
        } else {
            $error = "Failed to update password. Please try again.";
        }
        $update->close();
    }
}

// Update Security Questions
if (isset($_POST['update_security_questions'])) {
    $current_password_questions = $_POST['current_password_questions'];
    $question_1 = htmlspecialchars(trim($_POST['question_1']));
    $answer_1 = trim($_POST['answer_1']);
    $question_2 = htmlspecialchars(trim($_POST['question_2']));
    $answer_2 = trim($_POST['answer_2']);
    $question_3 = htmlspecialchars(trim($_POST['question_3']));
    $answer_3 = trim($_POST['answer_3']);
    
    // Verify current password first
    if (!password_verify($current_password_questions, $data['pass'])) {
        $error = "Current password is incorrect!";
    } elseif (empty($question_1) || empty($answer_1) || empty($question_2) || empty($answer_2) || empty($question_3) || empty($answer_3)) {
        $error = "All questions and answers are required!";
    } elseif (strlen($answer_1) < 2 || strlen($answer_2) < 2 || strlen($answer_3) < 2) {
        $error = "Answers must be at least 2 characters long!";
    } else {
        // Hash answers for security
        $answer_1_hash = password_hash(strtolower($answer_1), PASSWORD_DEFAULT);
        $answer_2_hash = password_hash(strtolower($answer_2), PASSWORD_DEFAULT);
        $answer_3_hash = password_hash(strtolower($answer_3), PASSWORD_DEFAULT);
        
        if ($has_security_questions) {
            // Update existing questions
            $update = $conn->prepare("UPDATE security_questions SET question_1 = ?, answer_1_hash = ?, question_2 = ?, answer_2_hash = ?, question_3 = ?, answer_3_hash = ? WHERE unique_id = ?");
            $update->bind_param("sssssss", $question_1, $answer_1_hash, $question_2, $answer_2_hash, $question_3, $answer_3_hash, $user_id);
        } else {
            // Insert new questions
            $update = $conn->prepare("INSERT INTO security_questions (unique_id, question_1, answer_1_hash, question_2, answer_2_hash, question_3, answer_3_hash) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $update->bind_param("sssssss", $user_id, $question_1, $answer_1_hash, $question_2, $answer_2_hash, $question_3, $answer_3_hash);
        }
        
        if ($update->execute()) {
            $success = "Security questions updated successfully!";
            $has_security_questions = true;
            $show_security_questions = false; // Hide the form after successful update
        } else {
            $error = "Failed to update security questions. Please try again.";
        }
        $update->close();
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
    
    <title>Account Settings - PassCloud</title>
    
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    
    <link rel="stylesheet" href="assets/acc.css?v=<?php echo time(); ?>">
</head>
</body>
</html>
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
            <h1><i class="fas fa-user-cog"></i> Account Settings</h1>
            <p>Manage your account information and security settings</p>
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
        <div class="settings-section">
            <div class="section-header">
                <i class="fas fa-shield-alt"></i>
                <h2>Security Questions</h2>
                <span class="status-badge <?php echo $has_security_questions ? 'setup' : 'not-setup'; ?>">
                    <i class="fas fa-<?php echo $has_security_questions ? 'check' : 'exclamation-triangle'; ?>"></i>
                    <?php echo $has_security_questions ? 'Setup Complete' : 'Not Setup'; ?>
                </span>
            </div>

            <?php if(!$show_security_questions): ?>
            <div class="verify-section">
                <p>To view or update your security questions, please verify your current password.</p>
                <form method="post" style="max-width: 300px; margin: 0 auto;">
                    <div class="form-group">
                        <input type="password" name="current_password" class="form-control" 
                               placeholder="Enter current password" required>
                    </div>
                    <button type="submit" name="verify_password" class="btn btn-primary">
                        <i class="fas fa-shield-alt"></i> Verify Password
                    </button>
                </form>
            </div>
            <?php else: ?>
            <form method="post">
                <input type="hidden" name="current_password_questions" value="<?php echo htmlspecialchars($_POST['current_password'] ?? ''); ?>">
                
                <div class="question-item">
                    <div class="form-group">
                        <label for="question_1">Security Question 1</label>
                        <select name="question_1" id="question_1" class="form-control" required>
                            <option value="">Choose a question...</option>
                            <?php foreach($predefined_questions as $question): ?>
                                <option value="<?php echo $question; ?>" 
                                    <?php echo ($current_questions && $current_questions['question_1'] == $question) ? 'selected' : ''; ?>>
                                    <?php echo $question; ?>
                                </option>
                            <?php endforeach; ?>
                            <option value="custom">-- Or enter custom question --</option>
                        </select>
                        <input type="text" name="custom_question_1" id="custom_question_1" 
                               class="form-control" style="margin-top: 10px; display: none;" 
                               placeholder="Enter your custom question"
                               value="<?php echo $current_questions && !in_array($current_questions['question_1'], $predefined_questions) ? htmlspecialchars($current_questions['question_1']) : ''; ?>">
                    </div>
                    <div class="form-group">
                        <label for="answer_1">Your Answer</label>
                        <input type="text" name="answer_1" id="answer_1" class="form-control" 
                               placeholder="Enter your answer" required>
                    </div>
                </div>

                <div class="question-item">
                    <div class="form-group">
                        <label for="question_2">Security Question 2</label>
                        <select name="question_2" id="question_2" class="form-control" required>
                            <option value="">Choose a question...</option>
                            <?php foreach($predefined_questions as $question): ?>
                                <option value="<?php echo $question; ?>"
                                    <?php echo ($current_questions && $current_questions['question_2'] == $question) ? 'selected' : ''; ?>>
                                    <?php echo $question; ?>
                                </option>
                            <?php endforeach; ?>
                            <option value="custom">-- Or enter custom question --</option>
                        </select>
                        <input type="text" name="custom_question_2" id="custom_question_2" 
                               class="form-control" style="margin-top: 10px; display: none;" 
                               placeholder="Enter your custom question"
                               value="<?php echo $current_questions && !in_array($current_questions['question_2'], $predefined_questions) ? htmlspecialchars($current_questions['question_2']) : ''; ?>">
                    </div>
                    <div class="form-group">
                        <label for="answer_2">Your Answer</label>
                        <input type="text" name="answer_2" id="answer_2" class="form-control" 
                               placeholder="Enter your answer" required>
                    </div>
                </div>

                <div class="question-item">
                    <div class="form-group">
                        <label for="question_3">Security Question 3</label>
                        <select name="question_3" id="question_3" class="form-control" required>
                            <option value="">Choose a question...</option>
                            <?php foreach($predefined_questions as $question): ?>
                                <option value="<?php echo $question; ?>"
                                    <?php echo ($current_questions && $current_questions['question_3'] == $question) ? 'selected' : ''; ?>>
                                    <?php echo $question; ?>
                                </option>
                            <?php endforeach; ?>
                            <option value="custom">-- Or enter custom question --</option>
                        </select>
                        <input type="text" name="custom_question_3" id="custom_question_3" 
                               class="form-control" style="margin-top: 10px; display: none;" 
                               placeholder="Enter your custom question"
                               value="<?php echo $current_questions && !in_array($current_questions['question_3'], $predefined_questions) ? htmlspecialchars($current_questions['question_3']) : ''; ?>">
                    </div>
                    <div class="form-group">
                        <label for="answer_3">Your Answer</label>
                        <input type="text" name="answer_3" id="answer_3" class="form-control" 
                               placeholder="Enter your answer" required>
                    </div>
                </div>

                <button type="submit" name="update_security_questions" class="btn btn-primary btn-block">
                    <i class="fas fa-save"></i> Update Security Questions
                </button>
            </form>

            <div class="info-box">
                <h4><i class="fas fa-lightbulb"></i> Security Tips</h4>
                <p>Choose questions that are memorable but not easily guessable by others. Use answers that don't change over time and avoid information that can be found on social media.</p>
            </div>
            <?php endif; ?>
        </div>
    </div>

        <!-- Profile Information -->
        <div class="settings-section">
            <div class="section-header">
                <i class="fas fa-user"></i>
                <h2>Profile Information</h2>
            </div>
            

            <form method="post">
                <div class="form-group">
                    <label for="name">Full Name</label>
                    <input type="text" id="name" name="name" class="form-control" 
                           value="<?php echo htmlspecialchars($current_name); ?>" required>
                </div>
                <button type="submit" name="update_name" class="btn btn-primary">
                    <i class="fas fa-save"></i> Update Name
                </button>
            </form>
        </div>

        <!-- Email Address -->
        <div class="settings-section">
            <div class="section-header">
                <i class="fas fa-envelope"></i>
                <h2>Email Address</h2>
            </div>

            <form method="post">
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" class="form-control" 
                           value="<?php echo htmlspecialchars($current_email); ?>" required>
                </div>
                
            </form>
            <button onclick="opensoon()" class="btn btn-primary">
                    <i class="fas fa-save"></i> Update Email
                </button>
                <div id="soon"><p>email change was need an  authentication! so we will start authentication. stay tuned.</p></div>
        </div>

        <!-- Change Password -->
        <div class="settings-section">
            <div class="section-header">
                <i class="fas fa-lock"></i>
                <h2>Change Password</h2>
            </div>

            <form method="post">
                <div class="form-group">
                    <label for="current_password_pass">Current Password</label>
                    <input type="password" id="current_password_pass" name="current_password_pass" 
                           class="form-control" placeholder="Enter current password" required>
                </div>

                <div class="form-group">
                    <label for="new_password">New Password</label>
                    <input type="password" id="new_password" name="new_password" 
                           class="form-control" placeholder="Enter new password" required minlength="6"
                           oninput="checkPasswordStrength(this.value)">
                    <div class="password-strength">
                        <div class="password-strength-bar" id="passwordStrengthBar"></div>
                    </div>
                </div>

                <div class="form-group">
                    <label for="confirm_password">Confirm New Password</label>
                    <input type="password" id="confirm_password" name="confirm_password" 
                           class="form-control" placeholder="Confirm new password" required minlength="6"
                           oninput="checkPasswordMatch()">
                    <small id="passwordMatch" style="font-size: 0.8rem;"></small>
                </div>

                <button type="submit" name="update_password" class="btn btn-primary">
                    <i class="fas fa-key"></i> Change Password
                </button>
            </form>
        </div>

        <!-- Security Questions -->
        

    <footer>
        <p>&copy; <?php echo date("Y"); ?> PassCloud — Secure Your Digital Life</p>
    </footer>
    <script src="assets/acc.js?v=<?php echo time();?>"></script>
      <script nonce="<?php echo CSP_NONCE; ?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
    </script>
</body>
</html>