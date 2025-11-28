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
}

$success = '';
$error = '';

// Check if security questions already exist
$existing_questions = mysqli_query($conn, "SELECT * FROM security_questions WHERE unique_id = '$user_id'");
$has_questions = $existing_questions->num_rows > 0;
if($has_questions){
     header("location:dashboard.php");
}

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

// Save security questions
if (isset($_POST['save_questions'])) {
    $question_1 = htmlspecialchars(trim($_POST['question_1']));
    $answer_1 = trim($_POST['answer_1']);
    $question_2 = htmlspecialchars(trim($_POST['question_2']));
    $answer_2 = trim($_POST['answer_2']);
    $question_3 = htmlspecialchars(trim($_POST['question_3']));
    $answer_3 = trim($_POST['answer_3']);
    
    // Validate inputs
    if (empty($question_1) || empty($answer_1) || empty($question_2) || empty($answer_2) || empty($question_3) || empty($answer_3)) {
        $error = "All questions and answers are required!";
    } elseif (strlen($answer_1) < 2 || strlen($answer_2) < 2 || strlen($answer_3) < 2) {
        $error = "Answers must be at least 2 characters long!";
    } else {
        // Hash answers for security
        $answer_1_hash = password_hash(strtolower($answer_1), PASSWORD_DEFAULT);
        $answer_2_hash = password_hash(strtolower($answer_2), PASSWORD_DEFAULT);
        $answer_3_hash = password_hash(strtolower($answer_3), PASSWORD_DEFAULT);
        
        if ($has_questions) {
            // Update existing questions
            $update = $conn->prepare("UPDATE security_questions SET question_1 = ?, answer_1_hash = ?, question_2 = ?, answer_2_hash = ?, question_3 = ?, answer_3_hash = ? WHERE unique_id = ?");
            $update->bind_param("sssssss", $question_1, $answer_1_hash, $question_2, $answer_2_hash, $question_3, $answer_3_hash, $user_id);
        } else {
            // Insert new questions
            $update = $conn->prepare("INSERT INTO security_questions (unique_id, question_1, answer_1_hash, question_2, answer_2_hash, question_3, answer_3_hash) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $update->bind_param("sssssss", $user_id, $question_1, $answer_1_hash, $question_2, $answer_2_hash, $question_3, $answer_3_hash);
        }
        
        if ($update->execute()) {
            $success = "Security questions saved successfully!";
            $has_questions = true;
            header("location:dashboard.php");
        } else {
            $error = "Failed to save security questions. Please try again.";
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
    
    <title>Security questions - PassCloud</title>
    
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    
    <link rel="stylesheet" href="assets/secq.css?v=<?php echo time(); ?>">
</head>
<body>
    <header>
        <div class="logo">
            <i class="fas fa-cloud"></i>
            PassCloud
        </div>
        
        <a href="security_settings.php" class="back-btn">
            <i class="fas fa-arrow-left"></i>
            <span>Back to Security</span>
        </a>
        
    </header>

    <div class="container">
        <div class="page-title">
            <h1><i class="fas fa-shield-alt"></i> Security Questions</h1>
            <p>Set up security questions for account recovery</p>
            <span>you can skip this and Fill in account setting later.</span>  
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

        <div class="security-section">
            <div class="section-header">
                <i class="fas fa-question-circle"></i>
                <h2>Security Questions Setup</h2>
                <span class="status-badge <?php echo $has_questions ? 'setup' : 'not-setup'; ?>">
                    <i class="fas fa-<?php echo $has_questions ? 'check' : 'exclamation-triangle'; ?>"></i>
                    <?php echo $has_questions ? 'Setup Complete' : 'Not Setup'; ?>
                </span>
            </div>

            <form method="post">
                <div class="question-item">
                    <div class="form-group">
                        <label for="question_1">Security Question 1</label>
                        <select name="question_1" id="question_1" class="form-control" required>
                            <option value="">Choose a question...</option>
                            <?php foreach($predefined_questions as $question): ?>
                                <option value="<?php echo $question; ?>"><?php echo $question; ?></option>
                            <?php endforeach; ?>
                            <option value="custom">-- Or enter custom question --</option>
                        </select>
                        <input type="text" name="custom_question_1" id="custom_question_1" 
                               class="form-control" style="margin-top: 10px; display: none;" 
                               placeholder="Enter your custom question">
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
                                <option value="<?php echo $question; ?>"><?php echo $question; ?></option>
                            <?php endforeach; ?>
                            <option value="custom">-- Or enter custom question --</option>
                        </select>
                        <input type="text" name="custom_question_2" id="custom_question_2" 
                               class="form-control" style="margin-top: 10px; display: none;" 
                               placeholder="Enter your custom question">
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
                                <option value="<?php echo $question; ?>"><?php echo $question; ?></option>
                            <?php endforeach; ?>
                            <option value="custom">-- Or enter custom question --</option>
                        </select>
                        <input type="text" name="custom_question_3" id="custom_question_3" 
                               class="form-control" style="margin-top: 10px; display: none;" 
                               placeholder="Enter your custom question">
                    </div>
                    <div class="form-group">
                        <label for="answer_3">Your Answer</label>
                        <input type="text" name="answer_3" id="answer_3" class="form-control" 
                               placeholder="Enter your answer" required>
                    </div>
                </div>

                <button type="submit" name="save_questions" class="btn btn-primary btn-block">
                    <i class="fas fa-save"></i> Save Security Questions
                </button>
                

            </form>
                            <a  class="btn btn-primary btn-block"
                     href="dashboard.php"> skip
                            </a>

            <div class="info-box">
                <h4><i class="fas fa-lightbulb"></i> Security Tips</h4>
                <ul>
                    <li>Choose questions that are memorable but not easily guessable by others</li>
                    <li>Use answers that don't change over time</li>
                    <li>Avoid answers that can't be found on social media</li>
                    <li>Answers are case-insensitive but must be consistent</li>
                    <li>These questions will be used for account recovery if you forget your password</li>
                    
                </ul>
            </div>
        </div>
    </div>

    <footer>
        <p>&copy; <?php echo date("Y"); ?> PassCloud — Secure Your Digital Life</p>
    </footer>

    <script src="secq.js?v=<?php echo time();?>">

    </script>
     <script nonce="<?php echo CSP_NONCE; ?>">
        console.log('Secure script loaded');
    </script>
</body>
</html>