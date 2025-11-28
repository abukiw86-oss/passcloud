<?php
require 'db.php';
require_once 'security.php';

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = mysqli_real_escape_string($conn, $_POST['email']);
    $password = $_POST['password'];
    
    // Input validation
    if (empty($email) || empty($password)) {
        $error = "Please fill in all fields";
    } else {
        // Check if user exists
        $stmt = mysqli_prepare($conn, "SELECT unique_id, mail, pass, status, role FROM users WHERE mail = ?");
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $user = mysqli_fetch_assoc($result);
        
        if ($user) {
            // Check if account is banned
            if ($user['status'] === 'banned') {
                $error = "This account has been suspended. Please contact support.";
                logSecurityEvent('login_attempt_banned', 'high', "Attempted login to banned account: $email");
            }
            // Check if account is active
            elseif ($user['status'] === 'active' && password_verify($password, $user['pass  '])) {
                
                // Login successful - update session
                $_SESSION['uniq'] = $user['unique_id'];
                $_SESSION['user_email'] = $user['email'];
                $_SESSION['user_role'] = $user['role'];
                $_SESSION['login_time'] = time();
                
                // Update last login
                $update_stmt = mysqli_prepare($conn, "UPDATE users SET last_login = NOW() WHERE unique_id = ?");
                mysqli_stmt_bind_param($update_stmt, "s", $user['unique_id']);
                mysqli_stmt_execute($update_stmt);
                
                // Log successful login
                logSecurityEvent('login_success', 'low', "User logged in successfully");
                
                // Redirect based on role
                if ($user['role'] === 'admin') {
                    header("Location: admin.php");
                    exit;
                } else {
                    header("Location: dashboard.php");
                    exit;
                }
                
            } else {
                $error = "Invalid email or password";
                
                // Log failed attempt
                logSecurityEvent('login_failed', 'medium', "Failed login attempt for: $email");
                
                // Implement rate limiting
                if (!checkRateLimit('login_attempt_' . $_SERVER['REMOTE_ADDR'], 5, 900)) {
                    $error = "Too many failed attempts. Please try again in 15 minutes.";
                    logSecurityEvent('rate_limit_exceeded', 'high', "Rate limit exceeded for IP: " . $_SERVER['REMOTE_ADDR']);
                }
            }
        } else {
            $error = "Invalid email or password";
            logSecurityEvent('login_failed', 'medium', "Attempted login to non-existent account: $email");
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - PassCloud</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .login-container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
            width: 100%;
            max-width: 400px;
        }

        .login-header {
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }

        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-bottom: 1rem;
        }

        .logo i {
            font-size: 2rem;
        }

        .logo h1 {
            font-size: 1.8rem;
            font-weight: 700;
        }

        .login-header p {
            opacity: 0.9;
            font-size: 0.9rem;
        }

        .login-form {
            padding: 2rem;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: #374151;
            font-weight: 500;
        }

        .input-group {
            position: relative;
        }

        .input-group i {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #6b7280;
        }

        .input-group input {
            width: 100%;
            padding: 12px 15px 12px 45px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 1rem;
            transition: all 0.3s;
        }

        .input-group input:focus {
            outline: none;
            border-color: #2563eb;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        .btn {
            width: 100%;
            padding: 12px;
            background: #2563eb;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
        }

        .btn:hover {
            background: #1d4ed8;
        }

        .btn:disabled {
            background: #9ca3af;
            cursor: not-allowed;
        }

        .form-links {
            display: flex;
            justify-content: space-between;
            margin-top: 1rem;
            font-size: 0.9rem;
        }

        .form-links a {
            color: #2563eb;
            text-decoration: none;
        }

        .form-links a:hover {
            text-decoration: underline;
        }

        .alert {
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .alert-error {
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: #dc2626;
        }

        .alert-success {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            color: #16a34a;
        }

        .security-notice {
            background: #fffbeb;
            border: 1px solid #fef3c7;
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1.5rem;
            font-size: 0.8rem;
            color: #92400e;
        }

        .security-notice i {
            color: #f59e0b;
            margin-right: 8px;
        }

        .admin-notice {
            background: #dbeafe;
            border: 1px solid #93c5fd;
            border-radius: 8px;
            padding: 0.8rem;
            margin-top: 1rem;
            text-align: center;
            font-size: 0.8rem;
            color: #1e40af;
        }

        @media (max-width: 480px) {
            .login-container {
                margin: 10px;
            }
            
            .login-header,
            .login-form {
                padding: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <div class="logo">
                <i class="fas fa-cloud-shield-alt"></i>
                <h1>PassCloud</h1>
            </div>
            <p>Secure password management</p>
        </div>

        <form class="login-form" method="POST" action="">
            <?php if ($error): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i>
                    <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>

            <?php if ($success): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <?php echo htmlspecialchars($success); ?>
                </div>
            <?php endif; ?>

            <div class="form-group">
                <label for="email">Email Address</label>
                <div class="input-group">
                    <i class="fas fa-envelope"></i>
                    <input type="email" id="email" name="email" required 
                           value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>"
                           placeholder="Enter your email">
                </div>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <div class="input-group">
                    <i class="fas fa-lock"></i>
                    <input type="password" id="password" name="password" required 
                           placeholder="Enter your password">
                </div>
            </div>

            <button type="submit" class="btn">
                <i class="fas fa-sign-in-alt"></i> Sign In
            </button>

            <div class="form-links">
                <a href="forgot-password.php">Forgot Password?</a>
                <a href="signup.php">Create Account</a>
            </div>

            <div class="security-notice">
                <i class="fas fa-shield-alt"></i>
                <strong>Security Notice:</strong> All login attempts are logged and monitored for suspicious activity.
            </div>

            <div class="admin-notice">
                <i class="fas fa-user-shield"></i>
                Admin users will be redirected to the admin panel automatically.
            </div>
        </form>
    </div>

    <script>
        // Client-side validation
        document.querySelector('form').addEventListener('submit', function(e) {
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            
            if (!email || !password) {
                e.preventDefault();
                alert('Please fill in all fields');
                return false;
            }
            
            // Basic email validation
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                e.preventDefault();
                alert('Please enter a valid email address');
                return false;
            }
            
            return true;
        });

        // Show/hide password (optional enhancement)
        const passwordInput = document.getElementById('password');
        const passwordToggle = document.createElement('span');
        passwordToggle.innerHTML = '<i class="fas fa-eye"></i>';
        passwordToggle.style.position = 'absolute';
        passwordToggle.style.right = '15px';
        passwordToggle.style.top = '50%';
        passwordToggle.style.transform = 'translateY(-50%)';
        passwordToggle.style.cursor = 'pointer';
        passwordToggle.style.color = '#6b7280';
        
        passwordToggle.addEventListener('click', function() {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            this.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
        });

        document.querySelector('.input-group').appendChild(passwordToggle);
    </script>
</body>
</html>