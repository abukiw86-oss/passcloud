<?php
/**
 * PassCloud Security Configuration
 * Advanced Security Functions and Headers
 * Include with: require_once 'security.php';
 */

// Prevent direct access
if (!defined('SECURITY_LOADED')) {
    define('SECURITY_LOADED', true);
}

// ================= SESSION SECURITY =================
if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => $_SERVER['HTTP_HOST'] ?? 'localhost',
        'secure' => isset($_SERVER['HTTPS']),
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
   
}


// ================= SECURITY HEADERS =================
if (!headers_sent()) {
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: DENY");
    header("X-XSS-Protection: 1; mode=block");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
}

// ================= CSRF PROTECTION =================
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ================= CSP NONCE =================
if (!defined('CSP_NONCE')) {
    $csp_nonce = base64_encode(random_bytes(16));
    define('CSP_NONCE', $csp_nonce);
    
    if (!headers_sent()) {
        header("Content-Security-Policy: default-src 'self'; " .
            "script-src 'self' 'nonce-".CSP_NONCE."' https://cdnjs.cloudflare.com; " .
            "style-src 'self' 'nonce-".CSP_NONCE."' https://cdnjs.cloudflare.com 'unsafe-inline'; " .
            "img-src 'self' data: https:; " .
            "font-src 'self' https://cdnjs.cloudflare.com; " .
            "connect-src 'self'; " .
            "object-src 'none'; " .
            "base-uri 'self'; " .
            "form-action 'self';");
    }
}

// ================= SECURITY FUNCTIONS =================

/**
 * Session Timeout Management
 */
function checkSessionTimeout($timeout = 10) {
    if (isset($_SESSION['login_time'])) {
        $session_life = time() - $_SESSION['login_time'];
        if ($session_life > $timeout) {
            // Log the timeout
            logSecurityEvent('session_timeout', 'medium', "Session expired after {$timeout} seconds");
            
            // Destroy session and redirect
            session_destroy();
            header("Location: log.php?error=session_expired&redirect=" . urlencode($_SERVER['REQUEST_URI']));
            exit;
        } else {
            // Update login time for active usage (only if significant time passed)
            if ($session_life > 60) { // Update every minute at most
                $_SESSION['login_time'] = time();
            }
        }
    }
}

/**
 * Advanced Rate Limiting
 */
function checkRateLimit($key, $max_attempts = 5, $time_window = 900, $ban_time = 3600) {
    $rate_limit_key = "rate_limit_$key";
    $ban_key = "banned_$key";
    
    // Check if currently banned
    if (isset($_SESSION[$ban_key]) && time() < $_SESSION[$ban_key]) {
        logSecurityEvent('rate_limit_banned', 'high', "Access banned for key: $key");
        return false;
    }
    
    if (!isset($_SESSION[$rate_limit_key])) {
        $_SESSION[$rate_limit_key] = [
            'attempts' => 1,
            'first_attempt' => time(),
            'last_attempt' => time()
        ];
        return true;
    }
    
    $rate_data = $_SESSION[$rate_limit_key];
    
    // Reset if time window has passed
    if (time() - $rate_data['first_attempt'] > $time_window) {
        $_SESSION[$rate_limit_key] = [
            'attempts' => 1,
            'first_attempt' => time(),
            'last_attempt' => time()
        ];
        return true;
    }
    
    // Check if exceeded max attempts
    if ($rate_data['attempts'] >= $max_attempts) {
        // Ban for specified time
        $_SESSION[$ban_key] = time() + $ban_time;
        logSecurityEvent('rate_limit_exceeded', 'high', 
            "Rate limit exceeded for key: $key - Banned for {$ban_time} seconds");
        return false;
    }
    
    // Increment attempts
    $_SESSION[$rate_limit_key]['attempts']++;
    $_SESSION[$rate_limit_key]['last_attempt'] = time();
    
    return true;
}

/**
 * Comprehensive Input Sanitization
 */
function sanitizeInput($data, $type = 'string') {
    if (is_array($data)) {
        return array_map('sanitizeInput', $data);
    }
    
    $data = trim($data ?? '');
    $data = stripslashes($data);
    
    switch ($type) {
        case 'email':
            $data = filter_var($data, FILTER_SANITIZE_EMAIL);
            break;
        case 'url':
            $data = filter_var($data, FILTER_SANITIZE_URL);
            break;
        case 'int':
            $data = filter_var($data, FILTER_SANITIZE_NUMBER_INT);
            break;
        case 'float':
            $data = filter_var($data, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
            break;
        case 'string':
        default:
            $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            break;
    }
    
    return $data;
}

/**
 * Advanced Validation Functions
 */
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

function validateURL($url) {
    return filter_var($url, FILTER_VALIDATE_URL) !== false;
}

function validateInt($number, $min = null, $max = null) {
    $options = [];
    if ($min !== null) $options['min_range'] = $min;
    if ($max !== null) $options['max_range'] = $max;
    
    return filter_var($number, FILTER_VALIDATE_INT, ['options' => $options]) !== false;
}

function validateFloat($number, $min = null, $max = null) {
    $options = [];
    if ($min !== null) $options['min_range'] = $min;
    if ($max !== null) $options['max_range'] = $max;
    
    return filter_var($number, FILTER_VALIDATE_FLOAT, ['options' => $options]) !== false;
}

/**
 * Secure File Upload Validation
 */
function validateFileUpload($file, $allowed_types = [], $max_size = 5242880, $allowed_extensions = []) {
    $errors = [];
    
    // Check for upload errors
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $upload_errors = [
            UPLOAD_ERR_INI_SIZE => 'File exceeds upload_max_filesize directive',
            UPLOAD_ERR_FORM_SIZE => 'File exceeds MAX_FILE_SIZE directive',
            UPLOAD_ERR_PARTIAL => 'File was only partially uploaded',
            UPLOAD_ERR_NO_FILE => 'No file was uploaded',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
            UPLOAD_ERR_EXTENSION => 'PHP extension stopped the file upload'
        ];
        $errors[] = $upload_errors[$file['error']] ?? "Upload failed with error code: {$file['error']}";
        return [false, $errors];
    }
    
    // Check file size
    if ($file['size'] > $max_size) {
        $errors[] = "File size exceeds maximum allowed size of " . round($max_size / 1024 / 1024, 2) . "MB";
    }
    
    // Check if file is actually uploaded
    if (!is_uploaded_file($file['tmp_name'])) {
        $errors[] = "Possible file upload attack";
    }
    
    // Get file info
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    // Check MIME type
    if (!empty($allowed_types) && !in_array($mime_type, $allowed_types)) {
        $errors[] = "File type not allowed";
    }
    
    // Check file extension
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $dangerous_extensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'phar', 'html', 'htm', 'js'];
    
    if (in_array($extension, $dangerous_extensions)) {
        $errors[] = "Dangerous file type detected";
    }
    
    if (!empty($allowed_extensions) && !in_array($extension, $allowed_extensions)) {
        $errors[] = "File extension not allowed";
    }
    
    // Additional security checks
    if ($file['size'] == 0) {
        $errors[] = "File is empty";
    }
    
    return [empty($errors), $errors];
}

/**
 * Security Logging with Database Support
 */
function logSecurityEvent($event_type, $severity = 'medium', $details = '') {
    global $conn;
    
    $user_id = $_SESSION['uniq'] ?? 'system';
    $ip_address = getClientIP();
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $request_uri = $_SERVER['REQUEST_URI'] ?? 'unknown';
    
    // Log to database if available
    if (isset($conn) && is_object($conn)) {
        try {
            $stmt = mysqli_prepare($conn, 
                "INSERT INTO security_logs (user_id, event_type, ip_address, user_agent, severity, details, request_uri) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)"
            );
            if ($stmt) {
                mysqli_stmt_bind_param($stmt, "sssssss", $user_id, $event_type, $ip_address, $user_agent, $severity, $details, $request_uri);
                mysqli_stmt_execute($stmt);
                mysqli_stmt_close($stmt);
            }
        } catch (Exception $e) {
            // Fallback to file logging if database fails
            error_log("Security log database error: " . $e->getMessage());
        }
    }
    
    // Always log to file as backup
    $log_file = __DIR__ . '/../logs/security.log';
    $log_dir = dirname($log_file);
    
    // Create logs directory if it doesn't exist
    if (!is_dir($log_dir)) {
        mkdir($log_dir, 0755, recursive: true);
    }
    
    $timestamp = date('Y-m-d H:i:s');
    $log_entry = "[$timestamp] [$severity] $event_type - IP: $ip_address - User: $user_id - Details: $details - URI: $request_uri\n";
    
    file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);
}

/**
 * Get Client IP Address (with proxy support)
 */
function getClientIP() {
    $ip_keys = [
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'HTTP_CLIENT_IP',
        'REMOTE_ADDR'
    ];
    
    foreach ($ip_keys as $key) {
        if (isset($_SERVER[$key])) {
            foreach (explode(',', $_SERVER[$key]) as $ip) {
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/**
 * Secure Redirect with Validation
 */
function secureRedirect($url, $allowed_domains = []) {
    // Default allowed domains
    if (empty($allowed_domains)) {
        $allowed_domains = [$_SERVER['HTTP_HOST']];
    }
    
    // Validate URL
    if (filter_var($url, FILTER_VALIDATE_URL)) {
        $parsed = parse_url($url);
        
        // Only allow redirects to same domain or explicitly allowed domains
        if (in_array($parsed['host'] ?? '', $allowed_domains)) {
            header("Location: $url");
            exit;
        }
    }
    
    // Fallback to home page
    header("Location: /");
    exit;
}

/**
 * Generate Secure Random Tokens
 */
function generateToken($length = 32) {
    return bin2hex(random_bytes($length));
}

function generateNumericCode($length = 6) {
    $code = '';
    for ($i = 0; $i < $length; $i++) {
        $code .= random_int(0, 9);
    }
    return $code;
}

/**
 * Verify CSRF Token
 */
function verifyCsrfToken($token) {
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Password Strength Validation
 */
function validatePasswordStrength($password) {
    $errors = [];
    
    if (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long";
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter";
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter";
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number";
    }
    
    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        $errors[] = "Password must contain at least one special character";
    }
    
    return $errors;
}

/**
 * Get Sanitized Superglobals
 */
function getSanitizedPost() {
    return sanitizeInput($_POST);
}

function getSanitizedGet() {
    return sanitizeInput($_GET);
}

function getSanitizedRequest() {
    return sanitizeInput($_REQUEST);
}

// ================= CONSTANTS =================
define('CSRF_TOKEN', $_SESSION['csrf_token']);

// ================= SESSION TIMEOUT CHECK =================
checkSessionTimeout();

// ================= INITIAL SECURITY LOG =================
if (isset($_SESSION['uniq'])) {
    logSecurityEvent('page_access', 'low', "Accessed: " . ($_SERVER['REQUEST_URI'] ?? 'unknown'));
}
?>