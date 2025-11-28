<?php
require_once 'db.php';
require_once 'security.php';
session_start();

if (!isset($_SESSION['uniq']) || $_SESSION['user_role'] !== 'admin') {
    header("Location: log.php");
    exit;
}

// Handle system settings updates
if (isset($_POST['update_settings'])) {
    $settings_updated = [];
    
    // General Settings
    if (isset($_POST['site_name'])) {
        $site_name = mysqli_real_escape_string($conn, $_POST['site_name']);
        mysqli_query($conn, "UPDATE system_settings SET setting_value = '$site_name' WHERE setting_key = 'site_name'");
        $settings_updated[] = "Site Name";
    }
    
    if (isset($_POST['site_url'])) {
        $site_url = mysqli_real_escape_string($conn, $_POST['site_url']);
        mysqli_query($conn, "UPDATE system_settings SET setting_value = '$site_url' WHERE setting_key = 'site_url'");
        $settings_updated[] = "Site URL";
    }
    
    // Security Settings
    if (isset($_POST['max_login_attempts'])) {
        $max_attempts = intval($_POST['max_login_attempts']);
        mysqli_query($conn, "UPDATE system_settings SET setting_value = '$max_attempts' WHERE setting_key = 'max_login_attempts'");
        $settings_updated[] = "Max Login Attempts";
    }
    
    if (isset($_POST['session_timeout'])) {
        $session_timeout = intval($_POST['session_timeout']);
        mysqli_query($conn, "UPDATE system_settings SET setting_value = '$session_timeout' WHERE setting_key = 'session_timeout'");
        $settings_updated[] = "Session Timeout";
    }
    
    if (isset($_POST['password_min_length'])) {
        $min_length = intval($_POST['password_min_length']);
        mysqli_query($conn, "UPDATE system_settings SET setting_value = '$min_length' WHERE setting_key = 'password_min_length'");
        $settings_updated[] = "Password Minimum Length";
    }
    
    // Email Settings
    if (isset($_POST['smtp_host'])) {
        $smtp_host = mysqli_real_escape_string($conn, $_POST['smtp_host']);
        mysqli_query($conn, "UPDATE system_settings SET setting_value = '$smtp_host' WHERE setting_key = 'smtp_host'");
        $settings_updated[] = "SMTP Host";
    }
    
    if (isset($_POST['smtp_port'])) {
        $smtp_port = intval($_POST['smtp_port']);
        mysqli_query($conn, "UPDATE system_settings SET setting_value = '$smtp_port' WHERE setting_key = 'smtp_port'");
        $settings_updated[] = "SMTP Port";
    }
    
    if (isset($_POST['smtp_username'])) {
        $smtp_username = mysqli_real_escape_string($conn, $_POST['smtp_username']);
        mysqli_query($conn, "UPDATE system_settings SET setting_value = '$smtp_username' WHERE setting_key = 'smtp_username'");
        $settings_updated[] = "SMTP Username";
    }
    
    if (!empty($_POST['smtp_password'])) {
        $smtp_password = mysqli_real_escape_string($conn, $_POST['smtp_password']);
        mysqli_query($conn, "UPDATE system_settings SET setting_value = '$smtp_password' WHERE setting_key = 'smtp_password'");
        $settings_updated[] = "SMTP Password";
    }
    
    if (count($settings_updated) > 0) {
        $success = "Settings updated successfully: " . implode(", ", $settings_updated);
        logSecurityEvent('system_settings_updated', 'medium', "Updated settings: " . implode(", ", $settings_updated));
    }
}

// Handle backup creation
if (isset($_POST['create_backup'])) {
    $backup_file = 'backup_' . date('Y-m-d_H-i-s') . '.sql';
    $backup_path = __DIR__ . '/backups/' . $backup_file;
    
    // Create backups directory if it doesn't exist
    if (!is_dir(__DIR__ . '/backups')) {
        mkdir(__DIR__ . '/backups', 0755, true);
    }
    
    // Simple backup creation (in real implementation, use mysqldump)
    $tables = ['users', 'passwords', 'security_logs', 'sessions', 'system_settings'];
    $backup_content = "-- PassCloud Database Backup\n";
    $backup_content .= "-- Generated: " . date('Y-m-d H:i:s') . "\n\n";
    
    foreach ($tables as $table) {
        $result = mysqli_query($conn, "SHOW TABLES LIKE '$table'");
        if (mysqli_num_rows($result) > 0) {
            $backup_content .= "-- Table: $table\n";
            $data = mysqli_query($conn, "SELECT * FROM $table");
            while ($row = mysqli_fetch_assoc($data)) {
                $columns = implode("`, `", array_keys($row));
                $values = implode("', '", array_map('addslashes', array_values($row)));
                $backup_content .= "INSERT INTO `$table` (`$columns`) VALUES ('$values');\n";
            }
            $backup_content .= "\n";
        }
    }
    
    if (file_put_contents($backup_path, $backup_content)) {
        $backup_success = "Backup created successfully: $backup_file";
        logSecurityEvent('database_backup', 'low', "Database backup created: $backup_file");
    } else {
        $backup_error = "Failed to create backup file";
    }
}

// Get current settings
$settings_result = mysqli_query($conn, "SELECT * FROM system_settings");
$settings = [];
while ($row = mysqli_fetch_assoc($settings_result)) {
    $settings[$row['setting_key']] = $row['setting_value'];
}

// Get system info
$php_version = phpversion();
$mysql_version = mysqli_get_server_info($conn);
$server_software = $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown';
$upload_max_filesize = ini_get('upload_max_filesize');
$max_execution_time = ini_get('max_execution_time');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Settings - PassCloud Admin</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="assets/adminsys.css?v=<?php echo time(); ?>">

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
                <li><a href="admin-system.php" class="active"><i class="fas fa-cog"></i> System Settings</a></li>
                <li><a href="admin-reports.php"><i class="fas fa-chart-bar"></i> Reports</a></li>
                <li><a href="dashboard.php"><i class="fas fa-arrow-left"></i> Back to App</a></li>
                <li><a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
            </ul>
        </nav>

        <!-- Main Content -->
        <main class="main-content">
            <div class="admin-header">
                <h2>System Settings</h2>
                <div class="user-info">
                    <div class="user-avatar">A</div>
                    <span>Admin User</span>
                </div>
            </div>

            <!-- System Information -->
            <div class="info-grid">
                <div class="info-card">
                    <h4>PHP Version</h4>
                    <div class="value"><?php echo $php_version; ?></div>
                </div>
                <div class="info-card">
                    <h4>MySQL Version</h4>
                    <div class="value"><?php echo $mysql_version; ?></div>
                </div>
                <div class="info-card">
                    <h4>Server Software</h4>
                    <div class="value"><?php echo $server_software; ?></div>
                </div>
                <div class="info-card">
                    <h4>Max Upload Size</h4>
                    <div class="value"><?php echo $upload_max_filesize; ?></div>
                </div>
            </div>

            <!-- Tabs -->
            <div class="tabs">
                <button class="tab active" onclick="switchTab('general')">General Settings</button>
                <button class="tab" onclick="switchTab('security')">Security</button>
                <button class="tab" onclick="switchTab('email')">Email</button>
                <button class="tab" onclick="switchTab('backup')">Backup & Restore</button>
                <button class="tab" onclick="switchTab('maintenance')">Maintenance</button>
            </div>

            <?php if (isset($success)): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <?php echo htmlspecialchars($success); ?>
                </div>
            <?php endif; ?>

            <?php if (isset($backup_success)): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    <?php echo htmlspecialchars($backup_success); ?>
                </div>
            <?php endif; ?>

            <?php if (isset($backup_error)): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i>
                    <?php echo htmlspecialchars($backup_error); ?>
                </div>
            <?php endif; ?>

            <!-- General Settings Tab -->
            <div class="tab-content active" id="general">
                <form method="POST">
                    <div class="content-section">
                        <div class="section-header">
                            <h3><i class="fas fa-globe"></i> General Settings</h3>
                        </div>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="site_name">Site Name</label>
                                <input type="text" id="site_name" name="site_name" class="form-control" 
                                       value="<?php echo htmlspecialchars($settings['site_name'] ?? 'PassCloud'); ?>">
                                <div class="form-help">The name of your password manager application</div>
                            </div>
                            <div class="form-group">
                                <label for="site_url">Site URL</label>
                                <input type="url" id="site_url" name="site_url" class="form-control" 
                                       value="<?php echo htmlspecialchars($settings['site_url'] ?? 'http://localhost/passcloud'); ?>">
                                <div class="form-help">The base URL of your application</div>
                            </div>
                            <div class="form-group">
                                <label for="admin_email">Admin Email</label>
                                <input type="email" id="admin_email" name="admin_email" class="form-control" 
                                       value="<?php echo htmlspecialchars($settings['admin_email'] ?? 'admin@passcloud.com'); ?>">
                                <div class="form-help">Email address for system notifications</div>
                            </div>
                            <div class="form-group">
                                <label for="timezone">Timezone</label>
                                <select id="timezone" name="timezone" class="form-control">
                                    <option value="UTC" <?php echo ($settings['timezone'] ?? 'UTC') === 'UTC' ? 'selected' : ''; ?>>UTC</option>
                                    <option value="America/New_York" <?php echo ($settings['timezone'] ?? '') === 'America/New_York' ? 'selected' : ''; ?>>Eastern Time</option>
                                    <option value="Europe/London" <?php echo ($settings['timezone'] ?? '') === 'Europe/London' ? 'selected' : ''; ?>>London</option>
                                </select>
                                <div class="form-help">Server timezone for timestamps</div>
                            </div>
                        </div>
                    </div>

                    <div class="content-section">
                        <div class="section-header">
                            <h3><i class="fas fa-feather"></i> Appearance</h3>
                        </div>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="theme">Theme</label>
                                <select id="theme" name="theme" class="form-control">
                                    <option value="light" <?php echo ($settings['theme'] ?? 'light') === 'light' ? 'selected' : ''; ?>>Light</option>
                                    <option value="dark" <?php echo ($settings['theme'] ?? '') === 'dark' ? 'selected' : ''; ?>>Dark</option>
                                    <option value="auto" <?php echo ($settings['theme'] ?? '') === 'auto' ? 'selected' : ''; ?>>Auto</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="language">Language</label>
                                <select id="language" name="language" class="form-control">
                                    <option value="en" <?php echo ($settings['language'] ?? 'en') === 'en' ? 'selected' : ''; ?>>English</option>
                                    <option value="es" <?php echo ($settings['language'] ?? '') === 'es' ? 'selected' : ''; ?>>Spanish</option>
                                    <option value="fr" <?php echo ($settings['language'] ?? '') === 'fr' ? 'selected' : ''; ?>>French</option>
                                </select>
                            </div>
                        </div>
                    </div>

                    <button type="submit" name="update_settings" class="btn btn-primary">
                        <i class="fas fa-save"></i> Save General Settings
                    </button>
                </form>
            </div>

            <!-- Security Settings Tab -->
            <div class="tab-content" id="security">
                <form method="POST">
                    <div class="content-section">
                        <div class="section-header">
                            <h3><i class="fas fa-shield-alt"></i> Security Settings</h3>
                        </div>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="max_login_attempts">Max Login Attempts</label>
                                <input type="number" id="max_login_attempts" name="max_login_attempts" class="form-control" 
                                       value="<?php echo htmlspecialchars($settings['max_login_attempts'] ?? '5'); ?>" min="3" max="10">
                                <div class="form-help">Maximum failed login attempts before temporary lockout</div>
                            </div>
                            <div class="form-group">
                                <label for="session_timeout">Session Timeout (minutes)</label>
                                <input type="number" id="session_timeout" name="session_timeout" class="form-control" 
                                       value="<?php echo htmlspecialchars($settings['session_timeout'] ?? '30'); ?>" min="5" max="1440">
                                <div class="form-help">User session timeout in minutes</div>
                            </div>
                            <div class="form-group">
                                <label for="password_min_length">Password Minimum Length</label>
                                <input type="number" id="password_min_length" name="password_min_length" class="form-control" 
                                       value="<?php echo htmlspecialchars($settings['password_min_length'] ?? '8'); ?>" min="6" max="32">
                                <div class="form-help">Minimum characters required for user passwords</div>
                            </div>
                            <div class="form-group">
                                <label>
                                    <input type="checkbox" name="require_2fa" value="1" <?php echo ($settings['require_2fa'] ?? '0') === '1' ? 'checked' : ''; ?>> 
                                    Require Two-Factor Authentication
                                </label>
                                <div class="form-help">Force all users to enable 2FA</div>
                            </div>
                        </div>
                    </div>

                    <button type="submit" name="update_settings" class="btn btn-primary">
                        <i class="fas fa-save"></i> Save Security Settings
                    </button>
                </form>
            </div>

            <!-- Email Settings Tab -->
            <div class="tab-content" id="email">
                <form method="POST">
                    <div class="content-section">
                        <div class="section-header">
                            <h3><i class="fas fa-envelope"></i> Email Settings</h3>
                        </div>
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="smtp_host">SMTP Host</label>
                                <input type="text" id="smtp_host" name="smtp_host" class="form-control" 
                                       value="<?php echo htmlspecialchars($settings['smtp_host'] ?? 'smtp.gmail.com'); ?>">
                            </div>
                            <div class="form-group">
                                <label for="smtp_port">SMTP Port</label>
                                <input type="number" id="smtp_port" name="smtp_port" class="form-control" 
                                       value="<?php echo htmlspecialchars($settings['smtp_port'] ?? '587'); ?>">
                            </div>
                            <div class="form-group">
                                <label for="smtp_username">SMTP Username</label>
                                <input type="text" id="smtp_username" name="smtp_username" class="form-control" 
                                       value="<?php echo htmlspecialchars($settings['smtp_username'] ?? ''); ?>">
                            </div>
                            <div class="form-group">
                                <label for="smtp_password">SMTP Password</label>
                                <input type="password" id="smtp_password" name="smtp_password" class="form-control" 
                                       placeholder="Leave blank to keep current password">
                            </div>
                        </div>
                    </div>

                    <button type="submit" name="update_settings" class="btn btn-primary">
                        <i class="fas fa-save"></i> Save Email Settings
                    </button>
                </form>
            </div>

            <!-- Backup & Restore Tab -->
            <div class="tab-content" id="backup">
                <div class="content-section">
                    <div class="section-header">
                        <h3><i class="fas fa-database"></i> Database Backup</h3>
                    </div>
                    <p>Create a backup of your database for safety and recovery purposes.</p>
                    
                    <form method="POST" class="backup-actions">
                        <button type="submit" name="create_backup" class="btn btn-success">
                            <i class="fas fa-download"></i> Create Backup Now
                        </button>
                    </form>
                </div>

                <div class="content-section">
                    <div class="section-header">
                        <h3><i class="fas fa-upload"></i> Restore Database</h3>
                    </div>
                    <p>Restore your database from a previous backup file.</p>
                    <div class="form-group">
                        <label for="backup_file">Select Backup File</label>
                        <input type="file" id="backup_file" name="backup_file" class="form-control" accept=".sql">
                        <div class="form-help">Only .sql files created by PassCloud backup system</div>
                    </div>
                    <button type="button" class="btn btn-warning" onclick="alert('Restore functionality would be implemented here')">
                        <i class="fas fa-upload"></i> Restore from Backup
                    </button>
                </div>
            </div>

            <!-- Maintenance Tab -->
            <div class="tab-content" id="maintenance">
                <div class="content-section">
                    <div class="section-header">
                        <h3><i class="fas fa-tools"></i> System Maintenance</h3>
                    </div>
                    
                    <div class="form-grid">
                        <div class="form-group">
                            <button type="button" class="btn btn-warning" onclick="clearCache()">
                                <i class="fas fa-broom"></i> Clear System Cache
                            </button>
                            <div class="form-help">Clear temporary cache files</div>
                        </div>
                        
                        <div class="form-group">
                            <button type="button" class="btn btn-warning" onclick="optimizeDatabase()">
                                <i class="fas fa-hammer"></i> Optimize Database
                            </button>
                            <div class="form-help">Optimize database tables for better performance</div>
                        </div>
                        
                        <div class="form-group">
                            <button type="button" class="btn btn-danger" onclick="showResetDialog()">
                                <i class="fas fa-trash"></i> Reset System
                            </button>
                            <div class="form-help">Danger: Reset all system data (irreversible)</div>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

  <script nonce="<?php echo CSP_NONCE; ?>" src="assets/adminsystem.js?v=<?php echo time();?>">
        // Your secure inline JavaScript
        console.log('Secure script loaded');
    </script>
</body>
</html>