<?php
require_once 'db.php';
require_once 'security.php';
session_start();

// Check for remote logout requests
if (isset($_SESSION['uniq'])) {
    $user_id = $_SESSION['uniq'];
    $session_id = session_id();
    
    $logout_check = mysqli_query($conn, "SELECT * FROM session_logout_requests WHERE unique_id = '$user_id' AND session_id = '$session_id' AND completed = 0");
    if ($logout_check->num_rows > 0) {
        mysqli_query($conn, "UPDATE session_logout_requests SET completed = 1 WHERE unique_id = '$user_id' AND session_id = '$session_id'");
        session_destroy();
        header("Location: all/log.php?message=session_ended");
        exit;
    }
}

// Check if user is logged in
if (!isset($_SESSION['uniq'])) {
    header("Location: all/log.php");
    exit;
}

$user_id = $_SESSION['uniq'];
$current_session_id = session_id();

// Get user data
$select = mysqli_query($conn, "SELECT * FROM users WHERE unique_id = '$user_id'");
if($select->num_rows > 0) {
    $data = mysqli_fetch_array($select);
    $name = $data['name'];
    $email = $data['mail'];
}

// Initialize counters
$total_visitors = 0;
$unique_visitors = 0;
$today_visitors = 0;
$online_visitors = 0;

// Create analytics table if it doesn't exist
$create_table = mysqli_query($conn, "
    CREATE TABLE IF NOT EXISTS analytics (
        id INT AUTO_INCREMENT PRIMARY KEY,
        unique_id VARCHAR(50) NOT NULL,
        session_id VARCHAR(128) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        user_agent TEXT,
        device_type VARCHAR(20),
        browser VARCHAR(50),
        os VARCHAR(50),
        country VARCHAR(100),
        city VARCHAR(100),
        page_visited VARCHAR(255),
        referrer VARCHAR(500),
        visit_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_unique TINYINT DEFAULT 1,
        INDEX idx_unique_id (unique_id),
        INDEX idx_visit_time (visit_time),
        INDEX idx_session_id (session_id)
    )
");

// Create session_logout_requests table if it doesn't exist
$create_logout_table = mysqli_query($conn, "
    CREATE TABLE IF NOT EXISTS session_logout_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        unique_id VARCHAR(50) NOT NULL,
        session_id VARCHAR(128) NOT NULL,
        requested_by VARCHAR(128),
        requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        completed TINYINT DEFAULT 0,
        completed_at DATETIME NULL,
        INDEX idx_unique_id (unique_id),
        INDEX idx_session_id (session_id),
        INDEX idx_completed (completed)
    )
");

// Get client information
$user_agent = $_SERVER['HTTP_USER_AGENT'];
$ip_address = $_SERVER['REMOTE_ADDR'];
$page_visited = $_SERVER['REQUEST_URI'];
$referrer = $_SERVER['HTTP_REFERER'] ?? 'Direct';

// Enhanced device detection (reusing your function)
function getDeviceInfo($user_agent) {
    $device_type = 'Desktop';
    $browser = 'Unknown Browser';
    $os = 'Unknown OS';
    $browser_icon = 'fa-globe';
    $device_icon = 'fa-laptop';
    
    if (preg_match('/(android|webos|iphone|ipad|ipod|blackberry|windows phone)/i', $user_agent)) {
        $device_type = 'Mobile';
        $device_icon = 'fa-mobile-alt';
    } elseif (preg_match('/(tablet|ipad|playbook|silk)/i', $user_agent)) {
        $device_type = 'Tablet';
        $device_icon = 'fa-tablet-alt';
    }
    
    if (preg_match('/chrome/i', $user_agent)) {
        $browser = 'Chrome';
        $browser_icon = 'fa-chrome';
    } elseif (preg_match('/firefox/i', $user_agent)) {
        $browser = 'Firefox';
        $browser_icon = 'fa-firefox';
    } elseif (preg_match('/safari/i', $user_agent) && !preg_match('/chrome/i', $user_agent)) {
        $browser = 'Safari';
        $browser_icon = 'fa-safari';
    } elseif (preg_match('/edge/i', $user_agent)) {
        $browser = 'Edge';
        $browser_icon = 'fa-edge';
    } elseif (preg_match('/opera/i', $user_agent)) {
        $browser = 'Opera';
        $browser_icon = 'fa-opera';
    }
    
    if (preg_match('/windows/i', $user_agent)) {
        $os = 'Windows';
    } elseif (preg_match('/macintosh|mac os x/i', $user_agent)) {
        $os = 'macOS';
    } elseif (preg_match('/linux/i', $user_agent)) {
        $os = 'Linux';
    } elseif (preg_match('/android/i', $user_agent)) {
        $os = 'Android';
    } elseif (preg_match('/iphone|ipad/i', $user_agent)) {
        $os = 'iOS';
    }
    
    return [
        'device_type' => $device_type,
        'browser' => $browser,
        'os' => $os,
        'device_name' => $os . ' ' . $device_type,
        'browser_icon' => $browser_icon,
        'device_icon' => $device_icon
    ];
}

$device_info = getDeviceInfo($user_agent);

// Check if this is a unique visit (based on session and IP within last 30 minutes)
$visit_hash = md5($ip_address . $user_agent . $user_id);
$recent_visit = mysqli_query($conn, "
    SELECT id FROM analytics 
    WHERE unique_id = '$user_id' 
    AND ip_address = '$ip_address' 
    AND session_id = '$current_session_id'
    AND visit_time > DATE_SUB(NOW(), INTERVAL 30 MINUTE)
    LIMIT 1
");

$is_unique_visit = $recent_visit->num_rows === 0;

// Record the visit
if ($is_unique_visit) {
    mysqli_query($conn, "
        INSERT INTO analytics (unique_id, session_id, ip_address, user_agent, device_type, browser, os, page_visited, referrer, is_unique)
        VALUES ('$user_id', '$current_session_id', '$ip_address', '$user_agent', '{$device_info['device_type']}', '{$device_info['browser']}', '{$device_info['os']}', '$page_visited', '$referrer', 1)
    ");
} else {
    // Update last activity for existing session
    mysqli_query($conn, "
        UPDATE analytics 
        SET last_activity = NOW(), page_visited = '$page_visited'
        WHERE unique_id = '$user_id' 
        AND session_id = '$current_session_id'
    ");
}

// Handle session termination requests
$success = '';
$error = '';

if (isset($_POST['terminate_session'])) {
    $target_session_id = $_POST['session_id'];
    
    if ($target_session_id === $current_session_id) {
        $error = "You cannot terminate your current session from this page.";
    } else {
        $terminate_request = mysqli_query($conn, "
            INSERT INTO session_logout_requests (unique_id, session_id, requested_by) 
            VALUES ('$user_id', '$target_session_id', '$current_session_id')
        ");
        
        if ($terminate_request) {
            $success = "Session termination request sent! The session will be terminated shortly.";
        } else {
            $error = "Failed to send termination request.";
        }
    }
}

if (isset($_POST['terminate_all_sessions'])) {
    $other_sessions = mysqli_query($conn, "
        SELECT DISTINCT session_id 
        FROM analytics 
        WHERE unique_id = '$user_id' 
        AND session_id != '$current_session_id'
        AND last_activity > DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ");
    
    $success_count = 0;
    while($session = $other_sessions->fetch_assoc()) {
        $terminate_request = mysqli_query($conn, "
            INSERT INTO session_logout_requests (unique_id, session_id, requested_by) 
            VALUES ('$user_id', '{$session['session_id']}', '$current_session_id')
        ");
        if ($terminate_request) {
            $success_count++;
        }
    }
    
    if ($success_count > 0) {
        $success = "Termination requests sent to $success_count active sessions!";
    } else {
        $error = "No other active sessions found to terminate.";
    }
}

// Get statistics
$stats = mysqli_query($conn, "
    SELECT 
        COUNT(*) as total_visits,
        COUNT(DISTINCT session_id) as unique_sessions,
        COUNT(DISTINCT ip_address) as unique_ips,
        SUM(CASE WHEN visit_time >= CURDATE() THEN 1 ELSE 0 END) as today_visits,
        SUM(CASE WHEN last_activity >= DATE_SUB(NOW(), INTERVAL 5 MINUTE) THEN 1 ELSE 0 END) as online_now
    FROM analytics 
    WHERE unique_id = '$user_id'
")->fetch_assoc();

$total_visitors = $stats['total_visits'] ?? 0;
$unique_visitors = $stats['unique_sessions'] ?? 0;
$today_visitors = $stats['today_visits'] ?? 0;
$online_visitors = $stats['online_now'] ?? 0;

// Get active sessions for termination management
$active_sessions = mysqli_query($conn, "
    SELECT 
        session_id,
        ip_address,
        browser,
        os,
        device_type,
        page_visited,
        last_activity,
        TIMESTAMPDIFF(MINUTE, last_activity, NOW()) as minutes_ago,
        CASE 
            WHEN TIMESTAMPDIFF(MINUTE, last_activity, NOW()) < 5 THEN 'active'
            WHEN TIMESTAMPDIFF(MINUTE, last_activity, NOW()) < 30 THEN 'recent'
            ELSE 'idle'
        END as activity_status
    FROM analytics 
    WHERE unique_id = '$user_id' 
    AND last_activity > DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ORDER BY last_activity DESC
");

// Get pending termination requests
$pending_terminations = mysqli_query($conn, "
    SELECT sr.*, a.browser, a.os, a.device_type 
    FROM session_logout_requests sr
    LEFT JOIN analytics a ON sr.session_id = a.session_id 
    WHERE sr.unique_id = '$user_id' 
    AND sr.completed = 0
    ORDER BY sr.requested_at DESC
");

// Get popular pages
$popular_pages = mysqli_query($conn, "
    SELECT page_visited, COUNT(*) as visit_count
    FROM analytics 
    WHERE unique_id = '$user_id'
    GROUP BY page_visited 
    ORDER BY visit_count DESC 
    LIMIT 10
");

// Get browser statistics
$browser_stats = mysqli_query($conn, "
    SELECT browser, COUNT(*) as count 
    FROM analytics 
    WHERE unique_id = '$user_id'
    GROUP BY browser 
    ORDER BY count DESC
");

// Get device statistics
$device_stats = mysqli_query($conn, "
    SELECT device_type, COUNT(*) as count 
    FROM analytics 
    WHERE unique_id = '$user_id'
    GROUP BY device_type 
    ORDER BY count DESC
");

// Get daily visits for the last 7 days
$daily_stats = mysqli_query($conn, "
    SELECT 
        DATE(visit_time) as date,
        COUNT(*) as visits,
        COUNT(DISTINCT session_id) as unique_visits
    FROM analytics 
    WHERE unique_id = '$user_id' 
    AND visit_time >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
    GROUP BY DATE(visit_time)
    ORDER BY date DESC
    LIMIT 7
");

// Clean up old data (keep 90 days of history)
mysqli_query($conn, "DELETE FROM analytics WHERE visit_time < DATE_SUB(NOW(), INTERVAL 90 DAY)");
mysqli_query($conn, "DELETE FROM session_logout_requests WHERE requested_at < DATE_SUB(NOW(), INTERVAL 7 DAY)");
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
    
    <title>Devices - PassCloud</title>
    
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" 
          integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" 
          crossorigin="anonymous" 
          referrerpolicy="no-referrer">
    
    <link rel="stylesheet" href="assets/count.css?v=<?php echo time(); ?>">
</head>
<body>
    <header>
        <div class="logo">
            <i class="fas fa-chart-line"></i>
            <span>PassCloud Analytics</span>
        </div>
        
        <a href="dashboard.php" class="back-btn">
            <i class="fas fa-arrow-left"></i>
            <span>Back to Dashboard</span>
        </a>
    </header>

    <div class="container">
        <div class="page-title">
            <h1><i class="fas fa-analytics"></i> Analytics & Session Control</h1>
            <p>Monitor your traffic and manage active sessions across all devices</p>
        </div>

        <?php if($success): ?>
            <div class="message success">
                <i class="fas fa-check-circle"></i>
                <div>
                    <strong>Success!</strong> <?php echo $success; ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if($error): ?>
            <div class="message error">
                <i class="fas fa-exclamation-circle"></i>
                <div>
                    <strong>Error!</strong> <?php echo $error; ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- Statistics Overview -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-users"></i>
                </div>
                <div class="stat-number"><?php echo number_format($total_visitors); ?></div>
                <div class="stat-label">Total Visits</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-user-friends"></i>
                </div>
                <div class="stat-number"><?php echo number_format($unique_visitors); ?></div>
                <div class="stat-label">Unique Sessions</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-calendar-day"></i>
                </div>
                <div class="stat-number"><?php echo number_format($today_visitors); ?></div>
                <div class="stat-label">Today's Visits</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-signal"></i>
                </div>
                <div class="stat-number"><?php echo number_format($online_visitors); ?></div>
                <div class="stat-label">Online Now</div>
            </div>
        </div>

        <div class="content-grid">
            <!-- Main Content -->
            <div class="main-content">
                <!-- Session Management -->
                <div class="analytics-section">
                    <div class="section-header">
                        <h2><i class="fas fa-laptop"></i> Active Sessions</h2>
                        <form method="post">
                            <button type="submit" name="terminate_all_sessions" class="btn btn-danger" 
                                    onclick="return confirm('Are you sure you want to terminate all other sessions? They will be logged out on their next request.')">
                                <i class="fas fa-skull-crossbones"></i> Terminate All Other Sessions
                            </button>
                        </form>
                    </div>

                    <div class="session-list">
                        <?php if($active_sessions->num_rows > 0): ?>
                            <?php while($session = $active_sessions->fetch_assoc()): ?>
                                <?php 
                                    $is_current = $session['session_id'] === $current_session_id;
                                    $has_pending_termination = mysqli_query($conn, "
                                        SELECT * FROM session_logout_requests 
                                        WHERE session_id = '{$session['session_id']}' 
                                        AND completed = 0
                                    ")->num_rows > 0;
                                ?>
                                <div class="session-item <?php echo $is_current ? 'current' : $session['activity_status']; ?>">
                                    <div class="session-info">
                                        <div class="session-icon">
                                            <i class="fas fa-<?php echo strtolower($session['device_type']) === 'mobile' ? 'mobile-alt' : (strtolower($session['device_type']) === 'tablet' ? 'tablet-alt' : 'laptop'); ?>"></i>
                                        </div>
                                        <div class="session-details">
                                            <h4>
                                                <?php echo htmlspecialchars($session['browser']); ?> on <?php echo htmlspecialchars($session['os']); ?>
                                                <?php if($is_current): ?>
                                                    <span class="badge current-badge">Current Session</span>
                                                <?php elseif($has_pending_termination): ?>
                                                    <span class="badge" style="background: var(--error); color: white;">Termination Pending</span>
                                                <?php else: ?>
                                                    <span class="badge <?php echo $session['activity_status'] === 'idle' ? 'idle-badge' : 'activity-badge'; ?>">
                                                        <?php echo ucfirst($session['activity_status']); ?>
                                                    </span>
                                                <?php endif; ?>
                                            </h4>
                                            <div class="session-meta">
                                                <span class="meta-item">
                                                    <i class="fas fa-network-wired"></i>
                                                    <?php echo htmlspecialchars($session['ip_address']); ?>
                                                </span>
                                                <span class="meta-item">
                                                    <i class="fas fa-clock"></i>
                                                    <?php 
                                                        if ($session['minutes_ago'] < 1) {
                                                            echo 'Just now';
                                                        } elseif ($session['minutes_ago'] < 60) {
                                                            echo $session['minutes_ago'] . ' minutes ago';
                                                        } else {
                                                            echo floor($session['minutes_ago'] / 60) . ' hours ago';
                                                        }
                                                    ?>
                                                </span>
                                                <span class="meta-item">
                                                    <i class="fas fa-file"></i>
                                                    <?php echo htmlspecialchars(basename($session['page_visited']) ?: 'Home'); ?>
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="session-actions">
                                        <?php if(!$is_current && !$has_pending_termination): ?>
                                            <form method="post">
                                                <input type="hidden" name="session_id" value="<?php echo $session['session_id']; ?>">
                                                <button type="submit" name="terminate_session" class="btn btn-danger" 
                                                        onclick="return confirm('Are you sure you want to terminate this session? They will be logged out on their next request.')">
                                                    <i class="fas fa-times"></i> Terminate
                                                </button>
                                            </form>
                                        <?php elseif($is_current): ?>
                                            <span class="btn" style="background: var(--success); color: white; cursor: default;">
                                                <i class="fas fa-check"></i> Current
                                            </span>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <div class="session-item">
                                <div class="session-info">
                                    <i class="fas fa-info-circle"></i>
                                    <span>No active sessions found</span>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Pending Terminations -->
                <?php if($pending_terminations->num_rows > 0): ?>
                <div class="analytics-section">
                    <div class="section-header">
                        <h2><i class="fas fa-clock"></i> Pending Terminations</h2>
                    </div>
                    <div class="session-list">
                        <?php while($termination = $pending_terminations->fetch_assoc()): ?>
                            <div class="termination-item">
                                <div class="session-info">
                                    <div class="session-icon">
                                        <i class="fas fa-exclamation-triangle"></i>
                                    </div>
                                    <div class="session-details">
                                        <h4>Session Termination Requested</h4>
                                        <div class="session-meta">
                                            <span class="meta-item">
                                                <i class="fas fa-browser"></i>
                                                <?php echo htmlspecialchars($termination['browser'] ?? 'Unknown'); ?> on <?php echo htmlspecialchars($termination['os'] ?? 'Unknown OS'); ?>
                                            </span>
                                            <span class="meta-item">
                                                <i class="fas fa-clock"></i>
                                                Requested <?php echo date('M j, g:i A', strtotime($termination['requested_at'])); ?>
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        <?php endwhile; ?>
                    </div>
                </div>
                <?php endif; ?>
            </div>

            <!-- Sidebar -->
            <div class="sidebar">
                <!-- Browser Statistics -->
                <div class="analytics-section">
                    <div class="section-header">
                        <h2><i class="fas fa-globe"></i> Browsers</h2>
                    </div>
                    <div class="analytics-list">
                        <?php if($browser_stats->num_rows > 0): ?>
                            <?php while($browser = $browser_stats->fetch_assoc()): ?>
                                <div class="analytics-item">
                                    <div class="item-info">
                                        <div class="item-icon">
                                            <i class="fab fa-<?php echo strtolower($browser['browser']); ?>"></i>
                                        </div>
                                        <span><?php echo htmlspecialchars($browser['browser']); ?></span>
                                    </div>
                                    <div class="item-count"><?php echo $browser['count']; ?></div>
                                </div>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <div class="analytics-item">
                                <span>No browser data available</span>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Last 7 Days -->
                <div class="analytics-section">
                    <div class="section-header">
                        <h2><i class="fas fa-chart-bar"></i> Last 7 Days</h2>
                    </div>
                    <div class="daily-stats">
                        <?php if($daily_stats->num_rows > 0): ?>
                            <?php while($day = $daily_stats->fetch_assoc()): ?>
                                <div class="daily-item">
                                    <div class="daily-date"><?php echo date('M j', strtotime($day['date'])); ?></div>
                                    <div class="daily-count"><?php echo $day['visits']; ?></div>
                                    <div class="stat-label">visits</div>
                                </div>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <div class="daily-item">
                                <div class="daily-date">No data</div>
                                <div class="daily-count">0</div>
                                <div class="stat-label">visits</div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <footer>
            <p><i class="fas fa-info-circle"></i> Analytics data is stored for 90 days. Session termination requests are processed immediately.</p>
            <p>Last updated: <?php echo date('F j, Y \a\t g:i A'); ?></p>
        </footer>
    </div>

     <script nonce="<?php echo CSP_NONCE; ?>" src="assets/count.jsv?=<?php echo time();?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
        <script src="assets/count.js?v=<?php echo time(); ?>"></script>
    </script>
</body>
</html>