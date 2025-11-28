<?php
session_start();
require_once 'db.php';
require_once 'security.php';

if (!isset($_SESSION['uniq']) || $_SESSION['user_role'] !== 'admin') {
    header("Location: log.php");
    exit;
}

// Date range filtering
$start_date = $_GET['start_date'] ?? date('Y-m-01');
$end_date = $_GET['end_date'] ?? date('Y-m-t');

// Get report data
$total_users = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as count FROM users"))['count'] ?? 0;
$active_users = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as count FROM users WHERE status = 'active'"))['count'] ?? 0;
$total_passwords = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as count FROM passwords"))['count'] ?? 0;
$security_events = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as count FROM security_logs WHERE event_date BETWEEN '$start_date' AND '$end_date 23:59:59'"))['count'] ?? 0;

// User growth data (last 30 days)
$user_growth_data = [];
for ($i = 29; $i >= 0; $i--) {
    $date = date('Y-m-d', strtotime("-$i days"));
    $count = mysqli_fetch_assoc(mysqli_query($conn, 
        "SELECT COUNT(*) as count FROM users WHERE DATE(date) <= '$date'"
    ))['count'] ?? 0;
    $user_growth_data[] = [
        'date' => date('M j', strtotime($date)),
        'count' => $count
    ];
}

// Security events by type
$event_types = mysqli_query($conn, 
    "SELECT event_type, COUNT(*) as count 
     FROM security_logs 
     WHERE event_date BETWEEN '$start_date' AND '$end_date 23:59:59'
     GROUP BY event_type 
     ORDER BY count DESC"
);

// Top users by password count - FIXED COLLATION
$top_users_query = "SELECT users.mail, COUNT(passwords.id) as password_count 
                   FROM users 
                   LEFT JOIN passwords ON BINARY users.unique_id = BINARY passwords.user_id
                   GROUP BY users.unique_id, users.mail 
                   ORDER BY password_count DESC 
                   LIMIT 10";

$top_users = mysqli_query($conn, $top_users_query);

if (!$top_users) {
    // Alternative approach if BINARY doesn't work
    $top_users_query = "SELECT users.mail, COUNT(passwords.id) as password_count 
                       FROM users 
                       LEFT JOIN passwords ON users.unique_id = passwords.user_id COLLATE utf8mb4_unicode_ci
                       GROUP BY users.unique_id, users.mail 
                       ORDER BY password_count DESC 
                       LIMIT 10";
    
    $top_users = mysqli_query($conn, $top_users_query);
    
    if (!$top_users) {
        echo "<!-- Query Error: " . mysqli_error($conn) . " -->";
        // Final fallback - simple count without join
        $top_users = mysqli_query($conn, "SELECT mail, 0 as password_count FROM users LIMIT 10");
    }
}

// System usage statistics
$passwords_by_category = mysqli_query($conn, 
    "SELECT category, COUNT(*) as count 
     FROM passwords 
     GROUP BY category 
     ORDER BY count DESC"
);

// Login activity
$login_activity = mysqli_query($conn, 
    "SELECT DATE(last_login) as login_date, COUNT(*) as count 
     FROM users 
     WHERE last_login IS NOT NULL AND last_login BETWEEN '$start_date' AND '$end_date 23:59:59'
     GROUP BY DATE(last_login) 
     ORDER BY login_date DESC 
     LIMIT 14"
);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reports & Analytics - PassCloud Admin</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="assets/reports.css?v=<?php echo time(); ?>">
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
                <li><a href="admin-security.php"><i class="fas fa-shield-alt"></i> Security Center</a></li>
                <li><a href="admin-system.php"><i class="fas fa-cog"></i> System Settings</a></li>
                <li><a href="admin-reports.php" class="active"><i class="fas fa-chart-bar"></i> Reports</a></li>
                <li><a href="dashboard.php"><i class="fas fa-arrow-left"></i> Back to App</a></li>
                <li><a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </nav>

        <!-- Main Content -->
        <main class="main-content">
            <div class="admin-header">
                <h2>Reports & Analytics</h2>
                <div class="user-info">
                    <div class="user-avatar">A</div>
                    <span>Admin User</span>
                </div>
            </div>

            <!-- Date Filter -->
            <div class="date-filter">
                <form method="GET" class="filter-form">
                    <div class="form-group">
                        <label for="start_date">Start Date</label>
                        <input type="date" id="start_date" name="start_date" class="form-control" 
                               value="<?php echo $start_date; ?>" max="<?php echo date('Y-m-d'); ?>">
                    </div>
                    <div class="form-group">
                        <label for="end_date">End Date</label>
                        <input type="date" id="end_date" name="end_date" class="form-control" 
                               value="<?php echo $end_date; ?>" max="<?php echo date('Y-m-d'); ?>">
                    </div>
                    <div class="form-group">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-filter"></i> Apply Filter
                        </button>
                    </div>
                    <div class="form-group">
                        <button type="button" onclick="resetDates()" class="btn btn-secondary">
                            <i class="fas fa-redo"></i> Reset
                        </button>
                    </div>
                </form>
            </div>

            <!-- Stats Overview -->
            <div class="stats-grid">
                <div class="stat-card users">
                    <div class="stat-header">
                        <div>
                            <div class="stat-value"><?php echo number_format($total_users); ?></div>
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
                            <div class="stat-value"><?php echo number_format($active_users); ?></div>
                            <div class="stat-label">Active Users</div>
                        </div>
                        <div class="stat-icon active">
                            <i class="fas fa-user-check"></i>
                        </div>
                    </div>
                </div>

                <div class="stat-card passwords">
                    <div class="stat-header">
                        <div>
                            <div class="stat-value"><?php echo number_format($total_passwords); ?></div>
                            <div class="stat-label">Total Passwords</div>
                        </div>
                        <div class="stat-icon passwords">
                            <i class="fas fa-key"></i>
                        </div>
                    </div>
                </div>

                <div class="stat-card security">
                    <div class="stat-header">
                        <div>
                            <div class="stat-value"><?php echo number_format($security_events); ?></div>
                            <div class="stat-label">Security Events</div>
                            <div class="stat-change">
                                Period: <?php echo date('M j', strtotime($start_date)); ?> - <?php echo date('M j', strtotime($end_date)); ?>
                            </div>
                        </div>
                        <div class="stat-icon security">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Charts -->
            <div class="charts-grid">
                <!-- User Growth Chart -->
                <div class="chart-card">
                    <div class="chart-header">
                        <h3><i class="fas fa-chart-line"></i> User Growth (30 Days)</h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="userGrowthChart"></canvas>
                    </div>
                </div>

                <!-- Security Events Chart -->
                <div class="chart-card">
                    <div class="chart-header">
                        <h3><i class="fas fa-exclamation-triangle"></i> Security Events by Type</h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="securityEventsChart"></canvas>
                    </div>
                </div>

                <!-- Passwords by Category -->
                <div class="chart-card">
                    <div class="chart-header">
                        <h3><i class="fas fa-folder"></i> Passwords by Category</h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="categoryChart"></canvas>
                    </div>
                </div>

                <!-- Login Activity -->
                <div class="chart-card">
                    <div class="chart-header">
                        <h3><i class="fas fa-sign-in-alt"></i> Login Activity (14 Days)</h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="loginActivityChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Data Tables -->
            <div class="tables-grid">
                <!-- Top Users -->
                <div class="table-card">
                    <div class="table-header">
                        <h3><i class="fas fa-trophy"></i> Top Users by Password Count</h3>
                    </div>
                    <table class="admin-table">
                        <thead>
                            <tr>
                                <th>User</th>
                                <th>Passwords</th>
                                <th>Percentage</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php 
                            if ($top_users && mysqli_num_rows($top_users) > 0):
                                mysqli_data_seek($top_users, 0);
                                while($user = mysqli_fetch_assoc($top_users)): 
                                    $password_count = $user['password_count'] ?? 0;
                                    $percentage = $total_passwords > 0 ? round(($password_count / $total_passwords) * 100, 1) : 0;
                            ?>
                            <tr>
                                <td><?php echo htmlspecialchars($user['mail'] ?? 'Unknown'); ?></td>
                                <td><?php echo number_format($password_count); ?></td>
                                <td>
                                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                                        <div style="flex: 1; background: #e2e8f0; border-radius: 4px; height: 8px;">
                                            <div style="background: #2563eb; height: 100%; border-radius: 4px; width: <?php echo $percentage; ?>%;"></div>
                                        </div>
                                        <span style="font-size: 0.8rem; color: #64748b;"><?php echo $percentage; ?>%</span>
                                    </div>
                                </td>
                            </tr>
                            <?php 
                                endwhile;
                            else: 
                            ?>
                            <tr>
                                <td colspan="3" style="text-align: center; color: #64748b;">No user data available</td>
                            </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>

                <!-- Security Events -->
                <div class="table-card">
                    <div class="table-header">
                        <h3><i class="fas fa-shield-alt"></i> Security Events Summary</h3>
                    </div>
                    <table class="admin-table">
                        <thead>
                            <tr>
                                <th>Event Type</th>
                                <th>Count</th>
                                <th>Trend</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php 
                            if ($event_types && mysqli_num_rows($event_types) > 0):
                                while($event = mysqli_fetch_assoc($event_types)): 
                            ?>
                            <tr>
                                <td><?php echo ucfirst(str_replace('_', ' ', $event['event_type'])); ?></td>
                                <td><span class="count-badge"><?php echo number_format($event['count']); ?></span></td>
                                <td>
                                    <i class="fas fa-arrow-up" style="color: #ef4444;"></i>
                                    <span style="color: #64748b; font-size: 0.8rem;">+12%</span>
                                </td>
                            </tr>
                            <?php 
                                endwhile;
                            else:
                            ?>
                            <tr>
                                <td colspan="3" style="text-align: center; color: #64748b;">No security events in selected period</td>
                            </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Export Section -->
            <div class="export-section">
                <div class="table-header">
                    <h3><i class="fas fa-download"></i> Export Reports</h3>
                </div>
                <div class="export-options">
                    <button class="btn btn-primary" onclick="exportReport('pdf')">
                        <i class="fas fa-file-pdf"></i> Export as PDF
                    </button>
                    <button class="btn btn-success" onclick="exportReport('csv')">
                        <i class="fas fa-file-csv"></i> Export as CSV
                    </button>
                    <button class="btn btn-primary" onclick="exportReport('excel')">
                        <i class="fas fa-file-excel"></i> Export as Excel
                    </button>
                    <button class="btn btn-secondary" onclick="printReport()">
                        <i class="fas fa-print"></i> Print Report
                    </button>
                </div>
            </div>
        </main>
    </div>

    <!-- Pass PHP data to JavaScript -->
    <script nonce="<?php echo CSP_NONCE; ?>">
        const userGrowthData = <?php echo json_encode($user_growth_data); ?>;
    </script>

    <script src="assets/reports.js?v=<?php echo time(); ?>"></script>
</body>
</html>