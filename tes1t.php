<?php
session_start();
require 'db.php'; // must define $conn (mysqli connection)

// ---------------- CSRF: create or reuse token ----------------
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

// ---------------- User identity (session) ----------------
$user_id = $_SESSION['uniq'] ?? 'guest';

// ---------------- Config ----------------
$upload_base = __DIR__ . '/secure_uploads/'; // make sure this matches your environment
if (!is_dir($upload_base)) mkdir($upload_base, 0750, true);

// Allowed MIME types (same as before)
$allowed_types = [
    'image/jpeg' => 'jpg',
    'image/png' => 'png',
    'image/gif' => 'gif',
    'application/pdf' => 'pdf',
    'text/plain' => 'txt',
    'application/zip' => 'zip',
    'application/msword' => 'doc',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx'
];

$upload_success = '';
$upload_error = '';

// ---------------- Handle Upload ----------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['uploadbok'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $csrf_token) {
        $upload_error = 'Security token validation failed.';
    } else {
        // Basic input sanitization
        $description = trim($_POST['description'] ?? '');
        $category = trim($_POST['category'] ?? 'other');

        // Validate description lightly
        if ($description === '') {
            $upload_error = 'Description is required.';
        } else {
            if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
                $upload_error = 'No file selected or upload error.';
            } else {
                $file_name = $_FILES['file']['name'];
                $file_tmp = $_FILES['file']['tmp_name'];
                $file_size = (int)$_FILES['file']['size'];

                // Reject suspicious filenames
                if (preg_match('/\.(php|phtml|phar|pht|php\d?|exe|bat|cmd|sh|pl|cgi|js|html?|svg)$/i', $file_name) || strpos($file_name, "\0") !== false) {
                    $upload_error = 'Malicious file name detected.';
                } elseif ($file_size > 10 * 1024 * 1024) {
                    $upload_error = 'File size exceeds 10MB.';
                } else {
                    $finfo = finfo_open(FILEINFO_MIME_TYPE);
                    $detected_type = $finfo ? finfo_file($finfo, $file_tmp) : null;
                    if ($finfo) finfo_close($finfo);

                    if (!$detected_type || !array_key_exists($detected_type, $allowed_types)) {
                        $upload_error = 'Invalid file type.';
                    } else {
                        $extension = $allowed_types[$detected_type];
                        $safe_name = bin2hex(random_bytes(8)) . '.' . $extension;

                        // store in upload base
                        $target_path = rtrim($upload_base, '/') . '/' . $safe_name;
                        if (move_uploaded_file($file_tmp, $target_path)) {
                            chmod($target_path, 0640);

                            // Insert record
                            $stmt = $conn->prepare("INSERT INTO uploaded_files (unique_id, filename, description, category, date) VALUES (?, ?, ?, ?, NOW())");
                            if ($stmt) {
                                $stmt->bind_param('ssss', $user_id, $safe_name, $description, $category);
                                if ($stmt->execute()) {
                                    $upload_success = 'File uploaded successfully!';
                                } else {
                                    $upload_error = 'Database error: Unable to save file.';
                                    // remove file if db insert fails
                                    @unlink($target_path);
                                }
                                $stmt->close();
                            } else {
                                $upload_error = 'Database error: Unable to prepare statement.';
                                @unlink($target_path);
                            }
                        } else {
                            $upload_error = 'Failed to move uploaded file.';
                        }
                    }
                }
            }
        }
    }
}

// ---------------- Handle Delete ----------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_file'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $csrf_token) {
        $upload_error = 'Security token validation failed for delete.';
    } else {
        $file_id = intval($_POST['file_id'] ?? 0);
        if ($file_id <= 0) {
            $upload_error = 'Invalid file identifier.';
        } else {
            // Fetch filename and owner
            $stmt = $conn->prepare("SELECT filename, unique_id FROM uploaded_files WHERE id = ? LIMIT 1");
            if ($stmt) {
                $stmt->bind_param('i', $file_id);
                $stmt->execute();
                $stmt->bind_result($filename_db, $owner_id);
                if ($stmt->fetch()) {
                    $stmt->close();
                    // Check ownership
                    if ($owner_id !== $user_id) {
                        $upload_error = 'Permission denied: You do not own this file.';
                    } else {
                        // Attempt to delete the file from filesystem
                        $file_path = rtrim($upload_base, '/') . '/' . $filename_db;
                        $fs_error = false;
                        if (is_file($file_path)) {
                            if (!@unlink($file_path)) {
                                // If unlink fails, don't proceed with DB deletion
                                $fs_error = true;
                                $upload_error = 'Failed to delete file from server.';
                            }
                        }
                        if (!$fs_error) {
                            // Delete DB row
                            $del = $conn->prepare("DELETE FROM uploaded_files WHERE id = ? AND unique_id = ? LIMIT 1");
                            if ($del) {
                                $del->bind_param('is', $file_id, $user_id);
                                if ($del->execute()) {
                                    if ($del->affected_rows > 0) {
                                        $upload_success = 'File deleted successfully.';
                                    } else {
                                        $upload_error = 'File not deleted from database.';
                                    }
                                } else {
                                    $upload_error = 'Database error while deleting record.';
                                }
                                $del->close();
                            } else {
                                $upload_error = 'Database error: Unable to prepare delete statement.';
                            }
                        }
                    }
                } else {
                    $stmt->close();
                    $upload_error = 'File record not found.';
                }
            } else {
                $upload_error = 'Database error: Unable to prepare statement.';
            }
        }
    }
}

// ---------------- Fetch user's uploaded files ----------------
$files = [];
$stmt = $conn->prepare("SELECT id, filename, description, category, date FROM uploaded_files WHERE unique_id = ? ORDER BY date DESC");
if ($stmt) {
    $stmt->bind_param('s', $user_id);
    $stmt->execute();
    $res = $stmt->get_result();
    if ($res) {
        while ($r = $res->fetch_assoc()) $files[] = $r;
        $res->free();
    }
    $stmt->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Secure File Upload</title>
<link rel="stylesheet" href="assets/file.css?v<?php echo time();?>">
<style>/*
    */
</style>
</head>
<body>
<header>🔒 Secure File Upload</header>
<div class="container">
    <?php if ($upload_error): ?>
        <div class="alert error"><?= htmlspecialchars($upload_error) ?></div>
    <?php elseif ($upload_success): ?>
        <div class="alert success"><?= htmlspecialchars($upload_success) ?></div>
    <?php endif; ?>

    <form method="POST" enctype="multipart/form-data" novalidate>
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
        <div class="col" style="flex:2">
            <label for="description">Description *</label>
            <textarea id="description" name="description" placeholder="Brief description..." required></textarea>
        </div>

        <div class="col">
            <label for="category">Category</label>
            <select id="category" name="category">
                <option value="document">Document</option>
                <option value="database">Database</option>
                <option value="password_export">Password Export</option>
                <option value="configuration">Configuration</option>
                <option value="other" selected>Other</option>
            </select>
        </div>

        <div class="col">
            <label for="file">Select File *</label>
            <input id="file" type="file" name="file" required>
        </div>

        <div style="flex-basis:100%;text-align:right">
            <button type="submit" name="uploadbok"><i>⬆️</i> Upload File</button>
        </div>
    </form>

    <h3>📁 Your Uploaded Files (<?= count($files) ?>)</h3>

    <?php if (count($files) > 0): ?>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Description</th>
                    <th>Category</th>
                    <th>Date</th>
                    <th>File</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($files as $i => $f): 
                    $index = $i + 1;
                    $safe_desc = htmlspecialchars($f['description']);
                    $safe_cat = htmlspecialchars($f['category']);
                    $safe_date = htmlspecialchars($f['date']);
                    $file_id = (int)$f['id'];
                    $filename = htmlspecialchars($f['filename']);
                    $file_url = 'secure_uploads/' . rawurlencode($f['filename']);
                ?>
                <tr>
                    <td><?= $index ?></td>
                    <td><?= $safe_desc ?></td>
                    <td><?= $safe_cat ?></td>
                    <td><?= $safe_date ?></td>
                    <td><a class="view-link" href="<?= $file_url ?>" target="_blank" rel="noopener noreferrer">View</a></td>
                    <td class="actions">
                        <!-- Delete form (POST) with CSRF & confirmation -->
                        <form method="POST" onsubmit="return confirmDelete(this);">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                            <input type="hidden" name="file_id" value="<?= $file_id ?>">
                            <button type="submit" name="delete_file" class="btn-danger" style="padding:8px 10px;border-radius:6px;color:#fff;border:none;cursor:pointer">Delete</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php else: ?>
        <p>No files uploaded yet.</p>
    <?php endif; ?>
</div>

<script>
function confirmDelete(form) {
    // can optionally show filename by reading hidden input file_id and mapping in JS if you want
    return confirm('Are you sure you want to permanently delete this file? This action cannot be undone.');
}
</script>
</body>
</html>
