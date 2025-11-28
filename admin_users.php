<?php
require_once 'db.php';
require_once 'security.php';
session_start();

if (!isset($_SESSION['uniq']) || $_SESSION['user_role'] !== 'admin') {
    header("Location: log.php");
    exit;
}

// Handle user actions
if (isset($_POST['action'])) {
    $user_id = $_POST['user_id'];
    
    switch ($_POST['action']) {
        case 'ban':
            mysqli_query($conn, "UPDATE users SET status = 'banned' WHERE unique_id = '$user_id'");
            $success = "User banned successfully";
            logSecurityEvent('user_banned', 'high', "User $user_id was banned by admin");
            break;
        case 'unban':
            mysqli_query($conn, "UPDATE users SET status = 'active' WHERE unique_id = '$user_id'");
            $success = "User unbanned successfully";
            logSecurityEvent('user_unbanned', 'medium', "User $user_id was unbanned by admin");
            break;
        case 'delete':
            mysqli_query($conn, "DELETE FROM users WHERE unique_id = '$user_id'");
            $success = "User deleted successfully";
            logSecurityEvent('user_deleted', 'high', "User $user_id was deleted by admin");
            break;
        case 'make_admin':
            mysqli_query($conn, "UPDATE users SET role = 'admin' WHERE unique_id = '$user_id'");
            $success = "User promoted to admin";
            logSecurityEvent('user_promoted', 'medium', "User $user_id was made admin");
            break;
        case 'remove_admin':
            mysqli_query($conn, "UPDATE users SET role = 'user' WHERE unique_id = '$user_id'");
            $success = "Admin privileges removed";
            logSecurityEvent('admin_demoted', 'medium', "User $user_id was demoted from admin");
            break;
    }
}

// Get all users
$users = mysqli_query($conn, "SELECT * FROM users ORDER BY date DESC");
$total_users = mysqli_num_rows($users);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management - PassCloud Admin</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="assets/adminuser.css?v=<?php echo time(); ?>">
 
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
                <li><a href="admin-users.php" class="active"><i class="fas fa-users"></i> User Management</a></li>
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
                <h2>User Management</h2>
                <div class="user-info">
                    <div class="user-avatar">A</div>
                    <span>Admin User</span>
                </div>
            </div>

            <!-- Stats -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value"><?php echo $total_users; ?></div>
                    <div class="stat-label">Total Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">
                        <?php 
                        $active_users = mysqli_query($conn, "SELECT COUNT(*) as count FROM users WHERE status = 'active'");
                        echo mysqli_fetch_assoc($active_users)['count'] ?? 0;
                        ?>
                    </div>
                    <div class="stat-label">Active Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">
                        <?php 
                        $admin_users = mysqli_query($conn, "SELECT COUNT(*) as count FROM users WHERE role = 'admin'");
                        echo mysqli_fetch_assoc($admin_users)['count'] ?? 0;
                        ?>
                    </div>
                    <div class="stat-label">Admin Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">
                        <?php 
                        $banned_users = mysqli_query($conn, "SELECT COUNT(*) as count FROM users WHERE status = 'banned'");
                        echo mysqli_fetch_assoc($banned_users)['count'] ?? 0;
                        ?>
                    </div>
                    <div class="stat-label">Banned Users</div>
                </div>
            </div>

            <!-- Users Table -->
            <div class="content-section">
                <div class="section-header">
                    <h3>All Users (<?php echo $total_users; ?>)</h3>
                    <div class="filters">
                        <div class="search-box">
                            <input type="text" placeholder="Search users..." id="searchInput">
                        </div>
                        <select class="filter-select" id="statusFilter">
                            <option value="">All Status</option>
                            <option value="active">Active</option>
                            <option value="inactive">Inactive</option>
                            <option value="banned">Banned</option>
                        </select>
                        <select class="filter-select" id="roleFilter">
                            <option value="">All Roles</option>
                            <option value="admin">Admin</option>
                            <option value="user">User</option>
                        </select>
                    </div>
                </div>

                <?php if (isset($success)): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i>
                        <?php echo htmlspecialchars($success); ?>
                    </div>
                <?php endif; ?>

                <table class="admin-table" id="usersTable">
                    <thead>
                        <tr>
                            <th>User ID</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Last Login</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while($user = mysqli_fetch_assoc($users)): ?>
                        <tr>
                            <td><?php echo substr($user['unique_id'], 0, 8) . '...'; ?></td>
                            <td><?php echo htmlspecialchars($user['mail'] ?? $user['email']); ?></td>
                            <td>
                                <span class="status-badge role-<?php echo $user['role']; ?>">
                                    <?php echo ucfirst($user['role']); ?>
                                </span>
                            </td>
                            <td>
                                <span class="status-badge status-<?php echo $user['status'] ?? 'active'; ?>">
                                    <?php echo ucfirst($user['status'] ?? 'active'); ?>
                                </span>
                            </td>
                            <td><?php echo $user['last_login'] ? date('M j, Y g:i A', strtotime($user['last_login'])) : 'Never'; ?></td>
                            <td><?php echo date('M j, Y', strtotime($user['date'])); ?></td>
                            <td>
                                <div class="action-buttons">
                                    <form method="POST" style="display: inline;">
                                        <input type="hidden" name="user_id" value="<?php echo $user['unique_id']; ?>">
                                        
                                        <?php if ($user['status'] === 'banned'): ?>
                                            <button type="submit" name="action" value="unban" class="btn btn-success btn-sm">Unban</button>
                                        <?php else: ?>
                                            <button type="submit" name="action" value="ban" class="btn btn-warning btn-sm">Ban</button>
                                        <?php endif; ?>
                                        
                                        <?php if ($user['role'] === 'admin' && $user['unique_id'] !== $_SESSION['uniq']): ?>
                                            <button type="submit" name="action" value="remove_admin" class="btn btn-warning btn-sm">Remove Admin</button>
                                        <?php elseif ($user['role'] === 'user'): ?>
                                            <button type="submit" name="action" value="make_admin" class="btn btn-primary btn-sm">Make Admin</button>
                                        <?php endif; ?>
                                        
                                        <?php if ($user['unique_id'] !== $_SESSION['uniq']): ?>
                                            <button type="submit" name="action" value="delete" class="btn btn-danger btn-sm" 
                                                    onclick="return confirm('Are you sure you want to delete this user? This action cannot be undone.')">Delete</button>
                                        <?php endif; ?>
                                    </form>
                                </div>
                            </td>
                        </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </main>
    </div>

<script src="assets/adminuser.js?v=<?php echo time(); ?>"></script>
     <script nonce="<?php echo CSP_NONCE; ?>" src="assets/adminuser.js?v=<?php echo time();?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
    </script>
</body>
</html>