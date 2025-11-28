<?php
require_once 'db.php';
require_once 'security.php';
session_start();


$error = '';
$success = '';
$step = isset($_GET['step']) ? intval($_GET['step']) : 1;
$questions_data = [];

// Step 1: Email verification
if (isset($_POST['verify_email'])) {
    $email = htmlspecialchars(trim($_POST['email']));
    
    $user = mysqli_query($conn, "SELECT * FROM users WHERE mail = '$email'");
    if ($user->num_rows > 0) {
        $user_data = $user->fetch_assoc();
        $_SESSION['recovery_user_id'] = $user_data['unique_id'];
        $_SESSION['recovery_email'] = $email;
        
        // Check if security questions are set up
        $questions = mysqli_query($conn, "SELECT * FROM security_questions WHERE unique_id = '{$user_data['unique_id']}'");
        if ($questions->num_rows > 0) {
            $questions_data = $questions->fetch_assoc();
            $step = 2;
        } else {
            $error = "Security questions are not set up for this account. Please contact support.";
        }
    } else {
        $error = "No account found with that email address.";
    }
}

// Step 2: Security questions
if (isset($_POST['verify_answers'])) {
    $user_id = $_SESSION['recovery_user_id'];
    $answer_1 = strtolower(trim($_POST['answer_1']));
    $answer_2 = strtolower(trim($_POST['answer_2']));
    $answer_3 = strtolower(trim($_POST['answer_3']));
    
    $questions = mysqli_query($conn, "SELECT * FROM security_questions WHERE unique_id = '$user_id'");
    
    if ($questions->num_rows > 0) {
        $q_data = $questions->fetch_assoc();
        
        if (password_verify($answer_1, $q_data['answer_1_hash']) &&
            password_verify($answer_2, $q_data['answer_2_hash']) &&
            password_verify($answer_3, $q_data['answer_3_hash'])) {
            
            $step = 3; // Proceed to password reset
        } else {
            $error = "One or more answers are incorrect. Please try again.";
            $questions_data = $q_data;
        }
    } else {
        $error = "Security questions not set up for this account.";
    }
}

// Step 3: Reset password
if (isset($_POST['reset_password'])) {
    $user_id = $_SESSION['recovery_user_id'];
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];
    
    if ($new_password !== $confirm_password) {
        $error = "Passwords do not match.";
    } elseif (strlen($new_password) < 6) {
        $error = "Password must be at least 6 characters long.";
    } else {
        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
        mysqli_query($conn, "UPDATE users SET pass = '$hashed_password' WHERE unique_id = '$user_id'");
        
        $success = "Password reset successfully! You can now login with your new password.";
        session_destroy();
        // Redirect to login after 3 seconds
        header("refresh:3;url=log.php");
    }
}?>

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
    
    <title>forgot password - PassCloud</title>
    
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    
    <link rel="stylesheet" href="assets/que.css?v=<?php echo time(); ?>">
</head>

   
    <div class="recovery-container">
        <div class="logo">
            <i class="fas fa-cloud"></i>
            PassCloud
        </div>

        <div class="recovery-card">
            <div class="recovery-header">
                <h1><i class="fas fa-key"></i> Password Recovery</h1>
                <p>Follow the steps to reset your password</p>
            </div>

            <!-- Step Indicator -->
            <div class="step-indicator">
                <div class="step <?php echo $step >= 1 ? 'completed' : ''; echo $step == 1 ? ' active' : ''; ?>">
                    <div class="step-circle">1</div>
                    <div class="step-label">Verify Email</div>
                </div>
                <div class="step <?php echo $step >= 2 ? 'completed' : ''; echo $step == 2 ? ' active' : ''; ?>">
                    <div class="step-circle">2</div>
                    <div class="step-label">Security Questions</div>
                </div>
                <div class="step <?php echo $step >= 3 ? 'completed' : ''; echo $step == 3 ? ' active' : ''; ?>">
                    <div class="step-circle">3</div>
                    <div class="step-label">New Password</div>
                </div>
            </div>

            <?php if(isset($success)): ?>
                <div class="message success">
                    <i class="fas fa-check-circle"></i>
                    <?php echo $success ?>
                    <br><small>Redirecting to login page...</small>
                </div>
            <?php endif; ?>

            <?php if(isset($error)): ?>
                <div class="message error">
                    <i class="fas fa-exclamation-circle"></i>
                    <?php echo $error ?>
                </div>
            <?php endif; ?>

            <!-- Step 1: Email Verification -->
            <?php if($step == 1): ?>
            <form method="post">
                <div class="form-group">
                    <label for="email">Enter Your Email Address</label>
                    <input type="email" id="email" name="email" class="form-control" 
                           placeholder="your@email.com" required>
                </div>
                <button type="submit" name="verify_email" class="btn btn-primary">
                    <i class="fas fa-envelope"></i> Verify Email
                </button>
            </form>
            <?php endif; ?>

            <!-- Step 2: Security Questions -->
            <?php if($step == 2 && !empty($questions_data)): ?>
            <form method="post">
                <div class="question-item">
                    <h4>Question 1:</h4>
                    <p><?php echo htmlspecialchars($questions_data['question_1']); ?></p>
                    <div class="form-group">
                        <input type="text" name="answer_1" class="form-control" 
                               placeholder="Your answer" required>
                    </div>
                </div>

                <div class="question-item">
                    <h4>Question 2:</h4>
                    <p><?php echo htmlspecialchars($questions_data['question_2']); ?></p>
                    <div class="form-group">
                        <input type="text" name="answer_2" class="form-control" 
                               placeholder="Your answer" required>
                    </div>
                </div>

                <div class="question-item">
                    <h4>Question 3:</h4>
                    <p><?php echo htmlspecialchars($questions_data['question_3']); ?></p>
                    <div class="form-group">
                        <input type="text" name="answer_3" class="form-control" 
                               placeholder="Your answer" required>
                    </div>
                </div>

                <button type="submit" name="verify_answers" class="btn btn-primary">
                    <i class="fas fa-check"></i> Verify Answers
                </button>
            </form>
            <?php endif; ?>

            <!-- Step 3: Reset Password -->
            <?php if($step == 3): ?>
            <form method="post">
                <div class="form-group">
                    <label for="new_password">New Password</label>
                    <input type="password" id="new_password" name="new_password" class="form-control" 
                           placeholder="Enter new password" required minlength="6"
                           oninput="checkPasswordStrength(this.value)">
                    <div class="password-strength">
                        <div class="password-strength-bar" id="passwordStrengthBar"></div>
                    </div>
                    <small style="color: rgba(255,255,255,0.6); font-size: 0.8rem;">
                        Password must be at least 6 characters long
                    </small>
                </div>

                <div class="form-group">
                    <label for="confirm_password">Confirm New Password</label>
                    <input type="password" id="confirm_password" name="confirm_password" class="form-control" 
                           placeholder="Confirm new password" required minlength="6"
                           oninput="checkPasswordMatch()">
                    <small id="passwordMatch" style="font-size: 0.8rem;"></small>
                </div>

                <button type="submit" name="reset_password" class="btn btn-primary">
                    <i class="fas fa-sync-alt"></i> Reset Password
                </button>
            </form>
            <?php endif; ?>

            <div class="back-link">
                <a href="log.php"><i class="fas fa-arrow-left"></i> Back to Login</a>
            </div>
        </div>

        <footer>
            <p>&copy; <?php echo date("Y"); ?> PassCloud — Secure Your Digital Life</p>
        </footer>
    </div>
   <script src="assets/que.js?v=<?php echo time();?>"></script>
    <script nonce="<?php echo CSP_NONCE; ?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
    </script>
</body>
</html>