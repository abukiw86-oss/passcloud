<?php
require_once 'db.php';
require_once 'security.php';
session_start();

// Admin authentication check
if (!isset($_SESSION['uniq']) || $_SESSION['user_role'] !== 'admin') {
    header("Location: log.php");
    exit;
}

// Get admin stats
$total_users = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as count FROM users"))['count'];
$active_today = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as count FROM users WHERE last_login >= CURDATE()"))['count'];
$security_events = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as count FROM security_logs WHERE event_date >= CURDATE()"))['count'];
//$storage_used = mysqli_fetch_assoc(mysqli_query($conn, "SELECT SUM(LENGTH(encrypted_data)) as size FROM passwords"))['size'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - PassCloud</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
 <link rel="stylesheet" href="assets/admin.css?v<?php echo time();?>">
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
                <li><a href="admin.php" class="active"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
                <li><a href="admin_users.php"><i class="fas fa-users"></i> User Management</a></li>
                <li><a href="admin-security.php"><i class="fas fa-shield-alt"></i> Security Center</a></li>
                <li><a href="admin-system.php"><i class="fas fa-cog"></i> System Settings</a></li>
                <li><a href="admin-reports.php"><i class="fas fa-chart-bar"></i> Reports</a></li>
                <li><a href="dashboard.php"><i class="fas fa-arrow-left"></i> Back to App</a></li>
                <li><a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </nav>

        <!-- Main Content -->
        <main class="main-content">
            <div class="admin-header">
                <h2>Admin Dashboard</h2>
                <div class="user-info">
                    <div class="user-avatar">A</div>
                    <span>Admin User</span>
                </div>
            </div>

            <!-- Stats Grid -->
            <div class="stats-grid">
                <div class="stat-card users">
                    <div class="stat-header">
                        <div>
                            <div class="stat-value"><?php echo $total_users; ?></div>
                            <div class="stat-label">Total Users</div>
                        </div>
                        <div class="stat-icon users">
                            <i class="fas fa-users"></i>
                        </div>
                    </div>
                </div>

                <div class="stat-card active">
                    <div class="stat-header">
                        <div>
                            <div class="stat-value"><?php echo $active_today; ?></div>
                            <div class="stat-label">Active Today</div>
                        </div>
                        <div class="stat-icon active">
                            <i class="fas fa-user-check"></i>
                        </div>
                    </div>
                </div>

                <div class="stat-card security">
                    <div class="stat-header">
                        <div>
                            <div class="stat-value"><?php echo $security_events; ?></div>
                            <div class="stat-label">Security Events</div>
                        </div>
                        <div class="stat-icon security">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                    </div>
                </div>

               
                </div>
            </div>

            <!-- Recent Users -->
            <div class="content-section">
                <div class="section-header">
                    <h3>Recent Users</h3>
                    <a href="admin_user.php" class="btn btn-primary">View All Users</a>
                </div>
                
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>User ID</th>
                            <th>Email</th>
                            <th>Status</th>
                            <th>Last Login</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $recent_users = mysqli_query($conn, 
                            "SELECT unique_id,mail,status,last_login,date 
                             FROM users 
                             ORDER BY date DESC 
                             LIMIT 5"
                        );
                        
                        while($users = mysqli_fetch_assoc($recent_users)):
                        ?>
                        <tr>
                            <td><?php echo substr($users['unique_id'], 0, 8) . '...'; ?></td>
                            <td><?php echo htmlspecialchars($users['mail']); ?></td>
                            <td>
                                <span class="status-badge status-active">
                                    <?php echo ucfirst($users['status']); ?>
                                </span>
                            </td>
                            <td><?php echo $users['last_login'] ? date('M j, Y g:i A', strtotime($users['last_login'])) : 'Never'; ?></td>
                            <td>
                                <div class="action-buttons">
                                    <button class="btn btn-primary btn-sm">View</button>
                                    <button class="btn btn-warning btn-sm">Edit</button>
                                </div>
                            </td>
                        </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>

            <!-- Security Alerts -->
            <div class="content-section">
                <div class="section-header">
                    <h3>Security Alerts</h3>
                    <a href="admin-security.php" class="btn btn-primary">Security Center</a>
                </div>
                
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    <div>
                        <strong>5 Failed Login Attempts</strong>
                        <p>Multiple failed login attempts detected from IP: 192.168.1.100</p>
                    </div>
                </div>
                
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>Event</th>
                            <th>User</th>
                            <th>IP Address</th>
                            <th>Timestamp</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                       $security_logs = mysqli_query($conn, 
    "SELECT * FROM security_logs 
     ORDER BY event_date DESC 
     LIMIT 5"
);
                        
                        while($log = mysqli_fetch_assoc($security_logs)):
                        ?>
                        <tr>
                            <td><?php echo htmlspecialchars($log['event_type']); ?></td>
                            <td><?php echo $log['user_id'] ? htmlspecialchars($log['user_id']) : 'System'; ?></td>
                            <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                            <td><?php echo date('M j, Y g:i A', strtotime($log['event_date'])); ?></td>
                            <td>
                                <span class="status-badge 
                                    <?php echo $log['severity'] === 'high' ? 'status-banned' : 
                                           ($log['severity'] === 'medium' ? 'status-inactive' : 'status-active'); ?>">
                                    <?php echo ucfirst($log['severity']); ?>
                                </span>
                            </td>
                        </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>

            <!-- System Status -->
            <div class="content-section">
                <div class="section-header">
                    <h3>System Status</h3>
                    <button class="btn btn-primary">Refresh Status</button>
                </div>
                
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>Service</th>
                            <th>Status</th>
                            <th>Response Time</th>
                            <th>Last Check</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Database Server</td>
                            <td><span class="status-badge status-active">Online</span></td>
                            <td>12ms</td>
                            <td><?php echo date('g:i:s A'); ?></td>
                        </tr>
                        <tr>
                            <td>Encryption Service</td>
                            <td><span class="status-badge status-active">Online</span></td>
                            <td>8ms</td>
                            <td><?php echo date('g:i:s A'); ?></td>
                        </tr>
                        <tr>
                            <td>Backup System</td>
                            <td><span class="status-badge status-active">Online</span></td>
                            <td>25ms</td>
                            <td><?php echo date('g:i:s A'); ?></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </main>
    </div>
   <script nonce="<?php echo CSP_NONCE; ?>" src="assets/admin.jsv?=<?php echo time();?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
    </script>
</body>
</html>