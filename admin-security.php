<?php
require_once 'db.php';
require_once 'security.php';
session_start();

if (!isset($_SESSION['uniq']) || $_SESSION['user_role'] !== 'admin') {
    header("Location: log.php");
    exit;
}

// Handle security actions
if (isset($_POST['action'])) {
    switch ($_POST['action']) {
        case 'clear_logs':
            $days = intval($_POST['days'] ?? 30);
            mysqli_query($conn, "DELETE FROM security_logs WHERE event_date < DATE_SUB(NOW(), INTERVAL $days DAY)");
            $success = "Security logs older than $days days cleared successfully";
            break;
        case 'block_ip':
            $ip = mysqli_real_escape_string($conn, $_POST['ip_address']);
            mysqli_query($conn, "INSERT INTO blocked_ips (ip_address, reason, blocked_by) VALUES ('$ip', 'Manual block by admin', '{$_SESSION['uniq']}')");
            $success = "IP address $ip blocked successfully";
            break;
        case 'unblock_ip':
            $ip = mysqli_real_escape_string($conn, $_POST['ip_address']);
            mysqli_query($conn, "DELETE FROM blocked_ips WHERE ip_address = '$ip'");
            $success = "IP address $ip unblocked successfully";
            break;
        case 'enable_maintenance':
            file_put_contents('maintenance.lock', 'enabled');
            $success = "Maintenance mode enabled";
            break;
        case 'disable_maintenance':
            if (file_exists('maintenance.lock')) {
                unlink('maintenance.lock');
            }
            $success = "Maintenance mode disabled";
            break;
    }
}

// Get security stats
$high_severity = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as count FROM security_logs WHERE severity = 'high' AND event_date >= CURDATE()"))['count'] ?? 0;
$failed_logins = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as count FROM security_logs WHERE event_type LIKE '%failed%' AND event_date >= CURDATE()"))['count'] ?? 0;
$blocked_ips = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as count FROM blocked_ips"))['count'] ?? 0;
$suspicious_activity = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as count FROM security_logs WHERE severity IN ('high', 'critical') AND event_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)"))['count'] ?? 0;

// Get recent security events
$security_events = mysqli_query($conn, "SELECT * FROM security_logs ORDER BY event_date DESC LIMIT 50");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Center - PassCloud Admin</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="assets/adminseq.css?v=<?php echo time(); ?>">
</head>
<body>
    <div class="admin-container">
        <!-- Sidebar -->
        <nav class="sidebar">
            <div class="admin-logo">
                <i class="fas fa-cloud-shield-alt"></i>
                <h1>PassCloud Admin</h1>
            </div>
            
            <ul class="nav-links">
                <li><a href="admin.php"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
                <li><a href="admin-users.php"><i class="fas fa-users"></i> User Management</a></li>
                <li><a href="admin-security.php" class="active"><i class="fas fa-shield-alt"></i> Security Center</a></li>
                <li><a href="admin-system.php"><i class="fas fa-cog"></i> System Settings</a></li>
                <li><a href="admin-reports.php"><i class="fas fa-chart-bar"></i> Reports</a></li>
                <li><a href="dashboard.php"><i class="fas fa-arrow-left"></i> Back to App</a></li>
                <li><a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </nav>

        <!-- Main Content -->
        <main class="main-content">
            <div class="admin-header">
                <h2>Security Center</h2>
                <div class="user-info">
                    <div class="user-avatar">A</div>
                    <span>Admin User</span>
                </div>
            </div>

            <!-- Security Stats -->
            <div class="security-stats">
                <div class="stat-card critical">
                    <div class="stat-header">
                        <div>
                            <div class="stat-value"><?php echo $high_severity; ?></div>
                            <div class="stat-label">High Severity Events Today</div>
                        </div>
                        <div class="stat-icon critical">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                    </div>
                </div>

                <div class="stat-card warning">
                    <div class="stat-header">
                        <div>
                            <div class="stat-value"><?php echo $failed_logins; ?></div>
                            <div class="stat-label">Failed Logins Today</div>
                        </div>
                        <div class="stat-icon warning">
                            <i class="fas fa-user-lock"></i>
                        </div>
                    </div>
                </div>

                <div class="stat-card info">
                    <div class="stat-header">
                        <div>
                            <div class="stat-value"><?php echo $blocked_ips; ?></div>
                            <div class="stat-label">Blocked IP Addresses</div>
                        </div>
                        <div class="stat-icon info">
                            <i class="fas fa-ban"></i>
                        </div>
                    </div>
                </div>

                <div class="stat-card success">
                    <div class="stat-header">
                        <div>
                            <div class="stat-value"><?php echo $suspicious_activity; ?></div>
                            <div class="stat-label">Suspicious Activities (7 days)</div>
                        </div>
                        <div class="stat-icon success">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Security Controls -->
            <div class="security-controls">
                <div class="control-card">
                    <h4><i class="fas fa-trash"></i> Clear Security Logs</h4>
                    <p>Remove old security logs to free up database space and improve performance.</p>
                    <form method="POST">
                        <div class="form-group">
                            <label>Delete logs older than:</label>
                            <select name="days" class="form-control">
                                <option value="7">7 days</option>
                                <option value="30" selected>30 days</option>
                                <option value="90">90 days</option>
                                <option value="365">1 year</option>
                            </select>
                        </div>
                        <button type="submit" name="action" value="clear_logs" class="btn btn-warning">
                            <i class="fas fa-trash"></i> Clear Logs
                        </button>
                    </form>
                </div>

                <div class="control-card">
                    <h4><i class="fas fa-ban"></i> IP Address Management</h4>
                    <p>Block or unblock IP addresses that show malicious activity.</p>
                    <form method="POST" class="form-group">
                        <label>IP Address:</label>
                        <input type="text" name="ip_address" placeholder="e.g., 192.168.1.100" class="form-control" required>
                        <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem;">
                            <button type="submit" name="action" value="block_ip" class="btn btn-danger btn-sm">
                                <i class="fas fa-ban"></i> Block IP
                            </button>
                            <button type="submit" name="action" value="unblock_ip" class="btn btn-success btn-sm">
                                <i class="fas fa-check"></i> Unblock IP
                            </button>
                        </div>
                    </form>
                </div>

                <div class="control-card">
                    <h4><i class="fas fa-tools"></i> Maintenance Mode</h4>
                    <p>Enable maintenance mode to temporarily disable public access for system updates.</p>
                    <form method="POST" style="display: flex; gap: 0.5rem;">
                        <?php if (file_exists('maintenance.lock')): ?>
                            <button type="submit" name="action" value="disable_maintenance" class="btn btn-success">
                                <i class="fas fa-play"></i> Disable Maintenance
                            </button>
                            <span style="color: #f59e0b; font-weight: 500;">Maintenance mode is ACTIVE</span>
                        <?php else: ?>
                            <button type="submit" name="action" value="enable_maintenance" class="btn btn-warning">
                                <i class="fas fa-pause"></i> Enable Maintenance
                            </button>
                            <span style="color: #10b981; font-weight: 500;">System is OPERATIONAL</span>
                        <?php endif; ?>
                    </form>
                </div>
            </div>

            <!-- Security Events -->
            <div class="content-section">
                <div class="section-header">
                    <h3>Security Events</h3>
                    <div class="tabs">
                        <button class="tab active" onclick="switchTab('all')">All Events</button>
                        <button class="tab" onclick="switchTab('critical')">Critical</button>
                        <button class="tab" onclick="switchTab('suspicious')">Suspicious</button>
                    </div>
                </div>

                <?php if (isset($success)): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i>
                        <?php echo htmlspecialchars($success); ?>
                    </div>
                <?php endif; ?>

                <div class="tab-content active" id="all">
                    <table class="admin-table">
                        <thead>
                            <tr>
                                <th>Event Type</th>
                                <th>User ID</th>
                                <th>IP Address</th>
                                <th>Severity</th>
                                <th>Timestamp</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php while($event = mysqli_fetch_assoc($security_events)): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($event['event_type']); ?></td>
                                <td><?php echo $event['user_id'] ? substr($event['user_id'], 0, 8) . '...' : 'System'; ?></td>
                                <td><?php echo htmlspecialchars($event['ip_address']); ?></td>
                                <td>
                                    <span class="severity-badge severity-<?php echo $event['severity']; ?>">
                                        <?php echo ucfirst($event['severity']); ?>
                                    </span>
                                </td>
                                <td><?php echo date('M j, Y g:i A', strtotime($event['event_date'])); ?></td>
                                <td><?php echo htmlspecialchars(substr($event['details'] ?? 'No details', 0, 50)) . '...'; ?></td>
                            </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Security Recommendations -->
            <div class="content-section">
                <div class="section-header">
                    <h3>Security Recommendations</h3>
                </div>
                <div class="security-controls">
                    <div class="control-card">
                        <h4><i class="fas fa-key"></i> Password Policy</h4>
                        <p>Review and update password complexity requirements for users.</p>
                        <button class="btn btn-primary">
                            <i class="fas fa-cog"></i> Configure Policy
                        </button>
                    </div>
                    <div class="control-card">
                        <h4><i class="fas fa-user-shield"></i> Two-Factor Authentication</h4>
                        <p>Enforce 2FA for all users or specific user groups.</p>
                        <button class="btn btn-primary">
                            <i class="fas fa-cog"></i> Manage 2FA
                        </button>
                    </div>
                    <div class="control-card">
                        <h4><i class="fas fa-clock"></i> Session Management</h4>
                        <p>Configure session timeout and concurrent login limits.</p>
                        <button class="btn btn-primary">
                            <i class="fas fa-cog"></i> Session Settings
                        </button>
                    </div>
                </div>
            </div>
        </main>
    </div>

  <script nonce="<?php echo CSP_NONCE; ?>" src="assets/adminseq.js?v=<?php echo time();?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
    </script>
</body>
</html>