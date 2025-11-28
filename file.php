<?php
// secure_upload.php
declare(strict_types=1);
session_start();
require_once __DIR__ . '/db.php'; // <-- must set $conn (mysqli)

// -------------------- Config --------------------
$MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
$ALLOWED_MIME = [
    'image/jpeg' => 'jpg',
    'image/png'  => 'png',
    'image/gif'  => 'gif',
    'application/pdf' => 'pdf',
    'text/plain' => 'txt',
    'text/csv'   => 'csv',
    'application/json' => 'json',
    'application/vnd.ms-excel' => 'xls',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => 'xlsx',
    'application/zip' => 'zip',
];
$ALLOWED_EXT = array_values($ALLOWED_MIME);
$FORBIDDEN_EXT = ['php','phtml','phar','php3','php4','php5','exe','bat','cmd','sh','pl','cgi','js','svg'];

// Upload storage (relative path). Recommended: place outside webroot in production.
$UPLOAD_BASE = realpath(__DIR__ . '/secure_uploads') ?: (__DIR__ . '/secure_uploads');
if (!is_dir($UPLOAD_BASE)) @mkdir($UPLOAD_BASE, 0750, true);

// Create protective .htaccess and index.html for Apache (harmless if not Apache)
$ht = $UPLOAD_BASE . '/.htaccess';
$htcontent = <<<HT
<FilesMatch "\.(php|phtml|phar|php3|php4|php5|htm|html|js|exe|bat|cmd|sh)$">
    Require all denied
</FilesMatch>
Options -Indexes
HT;
if (!file_exists($ht)) @file_put_contents($ht, $htcontent);
$indexHtml = $UPLOAD_BASE . '/index.html';
if (!file_exists($indexHtml)) @file_put_contents($indexHtml, '<html><body><h1>Forbidden</h1></body></html>');

// -------------------- Helpers --------------------
function sanitizeStr($s) { return trim((string)$s); }
function isDangerousFilename(string $name): bool {
    if (strpos($name, "\0") !== false) return true;
    // double/ext check
    if (preg_match('/\.(php|phtml|phar|php[0-9]?|exe|bat|cmd|sh|pl|cgi|js|html?|svg)/i', $name)) return true;
    // check intermediate parts for executable extensions (e.g. evil.php.jpg)
    $parts = explode('.', $name);
    if (count($parts) >= 3) {
        for ($i = 0; $i < count($parts)-1; $i++) {
            if (in_array(strtolower($parts[$i]), ['php','phtml','phar','php3','php4','php5','exe','js','sh','bat','cmd'], true)) return true;
        }
    }
    return false;
}


// -------------------- CSRF --------------------
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$CSRF = $_SESSION['csrf_token'];

// -------------------- Authentication guard --------------------
// This script expects a logged-in user with unique id in session.
if (!isset($_SESSION['uniq'])) {
    // Not logged in - redirect to login page (adjust as needed)
    header('Location: log.php');
    exit;
}
$USER_ID = (string)$_SESSION['uniq'];

// -------------------- Process Download (proxy) --------------------
if (isset($_GET['download'])) {
    $id = (int)$_GET['download'];
    if ($id <= 0) {
        http_response_code(400); exit('Bad request');
    }
    // Fetch file record and owner
    $stmt = $conn->prepare("SELECT filename, description, unique_id FROM uploaded_files WHERE id = ? LIMIT 1");
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $stmt->bind_result($filename_db, $desc_db, $owner_db);
    if ($stmt->fetch()) {
        $stmt->close();
        if ($owner_db !== $USER_ID) {
            http_response_code(403); exit('Forbidden');
        }
        $filePath = rtrim($UPLOAD_BASE, '/') . '/' . $filename_db;
        if (!is_file($filePath) || !is_readable($filePath)) {
            http_response_code(404); exit('File not found');
        }
        // Send safe headers and stream
        $basename = basename($desc_db ?: $filename_db);
        $safeName = preg_replace('/[^A-Za-z0-9\-\._ ]/', '_', $basename);
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $safeName . '"');
        header('Content-Length: ' . filesize($filePath));
        readfile($filePath);
        exit;
    } else {
        $stmt->close();
        http_response_code(404); exit('File not found');
    }
}

// -------------------- Handle POST actions (upload or delete) --------------------
$upload_success = '';
$upload_error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF
    $token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($CSRF, (string)$token)) {
        $upload_error = 'Security token validation failed.';
        logSecurityEvent('csrf_failed', "user=$USER_ID");
    } else {
        // ---------- Delete action ----------
        if (isset($_POST['delete_file'])) {
            $file_id = (int)($_POST['file_id'] ?? 0);
            if ($file_id <= 0) {
                $upload_error = 'Invalid file identifier.';
            } else {
                $stmt = $conn->prepare("SELECT filename, unique_id FROM uploaded_files WHERE id = ? LIMIT 1");
                $stmt->bind_param('i', $file_id);
                $stmt->execute();
                $stmt->bind_result($filename_db, $owner_db);
                if ($stmt->fetch()) {
                    $stmt->close();
                    if ($owner_db !== $USER_ID) {
                        $upload_error = 'Permission denied.';
                        logSecurityEvent('delete_permission', "user=$USER_ID file=$file_id owner=$owner_db");
                    } else {
                        $filePath = rtrim($UPLOAD_BASE, '/') . '/' . $filename_db;
                        $fs_ok = true;
                        if (is_file($filePath)) {
                            if (!@unlink($filePath)) {
                                $fs_ok = false;
                                $upload_error = 'Failed to delete file from server.';
                                logSecurityEvent('unlink_failed', "user=$USER_ID file=$filePath");
                            }
                        }
                        if ($fs_ok) {
                            $del = $conn->prepare("DELETE FROM uploaded_files WHERE id = ? AND unique_id = ? LIMIT 1");
                            $del->bind_param('is', $file_id, $USER_ID);
                            if ($del->execute()) {
                                if ($del->affected_rows > 0) {
                                    $upload_success = 'File deleted successfully.';
                                    logSecurityEvent('file_deleted', "user=$USER_ID file_id=$file_id");
                                } else {
                                    $upload_error = 'File record not removed.';
                                }
                            } else {
                                $upload_error = 'Database error while deleting record.';
                            }
                            $del->close();
                        }
                    }
                } else {
                    $stmt->close();
                    $upload_error = 'File record not found.';
                }
            }
        }
        // ---------- Upload action ----------
        elseif (isset($_POST['uploadbok'])) {
            $description = sanitizeStr($_POST['description'] ?? '');
            $category = sanitizeStr($_POST['category'] ?? 'other');
            if ($description === '') {
                $upload_error = 'Description is required.';
            } elseif (!isset($_FILES['file']) || !is_array($_FILES['file'])) {
                $upload_error = 'Please select a valid file to upload.';
            } else {
                $file = $_FILES['file'];
                if ($file['error'] !== UPLOAD_ERR_OK) {
                    $upload_error = 'File upload error code: ' . intval($file['error']);
                    logSecurityEvent('php_upload_error', "user=$USER_ID code=" . intval($file['error']));
                } else {
                    $origName = $file['name'];
                    if (isDangerousFilename($origName)) {
                        $upload_error = 'Malicious filename detected.';
                        logSecurityEvent('dangerous_filename', "user=$USER_ID name=$origName");
                    } elseif ((int)$file['size'] > $MAX_FILE_SIZE) {
                        $upload_error = 'File size must be less than 10MB.';
                    } else {
                        // detect mime
                        $finfo = finfo_open(FILEINFO_MIME_TYPE);
                        $mime = $finfo ? finfo_file($finfo, $file['tmp_name']) : null;
                        if ($finfo) finfo_close($finfo);
                        $mappedExt = $mime && array_key_exists($mime, $ALLOWED_MIME) ? $ALLOWED_MIME[$mime] : null;
                        // prefer mappedExt, fallback to original extension if safe
                        $clientExt = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
                        $finalExt = $mappedExt ?? $clientExt;
                        if (!$finalExt || in_array($finalExt, $FORBIDDEN_EXT, true) || !in_array($finalExt, $ALLOWED_EXT, true)) {
                            $upload_error = 'Invalid file type detected.';
                            logSecurityEvent('invalid_type', "user=$USER_ID mime=$mime ext=$clientExt");
                        } else {
                            // content checks for textual types (basic): reject embedded PHP or <script>
                            if (in_array($finalExt, ['html','htm','txt','json','csv','xml'], true)) {
                                $content = @file_get_contents($file['tmp_name']);
                                if ($content !== false && preg_match('/(<\?php|<script\b|<iframe\b|onerror=|onload=)/i', $content)) {
                                    $upload_error = 'File contains potentially harmful code.';
                                    logSecurityEvent('active_code', "user=$USER_ID file=$origName");
                                }
                            }
                            // proceed to move
                            if (empty($upload_error)) {
                                $subdir = date('Ym') . '/' . bin2hex(random_bytes(4));
                                $targetDir = rtrim($UPLOAD_BASE, '/') . '/' . $subdir;
                                if (!is_dir($targetDir)) @mkdir($targetDir, 0750, true);
                                // Ensure protective files in subdir
                                $htsub = $targetDir . '/.htaccess';
                                if (!file_exists($htsub)) @file_put_contents($htsub, $htcontent);
                                $safeFilename = substr($category,0,3) . '_' . uniqid('', true) . '_' . bin2hex(random_bytes(8)) . '.' . $finalExt;
                                $finalPath = $targetDir . '/' . $safeFilename;
                                if (@move_uploaded_file($file['tmp_name'], $finalPath)) {
                                    @chmod($finalPath, 0640);
                                    $relativeStored = $subdir . '/' . $safeFilename;
                                    $ins = $conn->prepare("INSERT INTO uploaded_files (unique_id, description, filename, category, date) VALUES (?, ?, ?, ?, NOW())");
                                    if ($ins) {
                                        $ins->bind_param('ssss', $USER_ID, $description, $relativeStored, $category);
                                        if ($ins->execute()) {
                                            $upload_success = 'File uploaded successfully!';
                                            logSecurityEvent('file_uploaded', "user=$USER_ID file=$relativeStored");
                                        } else {
                                            $upload_error = 'Database error: unable to save file info.';
                                            @unlink($finalPath);
                                            logSecurityEvent('db_insert_failed', "user=$USER_ID err=" . $conn->error);
                                        }
                                        $ins->close();
                                    } else {
                                        $upload_error = 'Database error: prepare failed.';
                                        @unlink($finalPath);
                                        logSecurityEvent('db_prepare_failed', "user=$USER_ID");
                                    }
                                } else {
                                    $upload_error = 'Failed to move uploaded file.';
                                    logSecurityEvent('move_failed', "user=$USER_ID tmp=" . $file['tmp_name']);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// -------------------- Fetch user's uploaded files --------------------
$files = [];
$stmt = $conn->prepare("SELECT id, description, filename, category, date FROM uploaded_files WHERE unique_id = ? ORDER BY date DESC");
if ($stmt) {
    $stmt->bind_param('s', $USER_ID);
    $stmt->execute();
    $res = $stmt->get_result();
    if ($res) {
        while ($row = $res->fetch_assoc()) $files[] = $row;
        $res->free();
    }
    $stmt->close();
}

// -------------------- Output HTML --------------------
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure File Upload</title>
<link rel="stylesheet" href="assets/file.css?v<?php echo time();?>">
</head>
<body>
<header>🔒 PassCloud — Secure File Upload</header>
<div class="container">
    <?php if (!empty($upload_error)): ?>
        <div class="alert error"><?= htmlspecialchars($upload_error) ?></div>
    <?php elseif (!empty($upload_success)): ?>
        <div class="alert success"><?= htmlspecialchars($upload_success) ?></div>
    <?php endif; ?>

    <form method="post" enctype="multipart/form-data" novalidate>
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($CSRF) ?>">
        <div class="form-grid">
            <div>
                <label for="description">Description *</label>
                <textarea id="description" name="description" rows="2" placeholder="Brief description..." required></textarea>
            </div>
            <div>
                <label for="category">Category</label>
                <select id="category" name="category">
                    <option value="document">Document</option>
                    <option value="database">Database</option>
                    <option value="password_export">Password Export</option>
                    <option value="configuration">Configuration</option>
                    <option value="other" selected>Other</option>
                </select>
            </div>
            <div>
                <label for="file">Select File *</label>
                <input id="file" type="file" name="file" required>
            </div>
        </div>

        <div style="margin-top:12px;text-align:right">
            <button type="submit" name="uploadbok">⬆️ Upload File</button>
        </div>
    </form>

    <h3 style="margin-top:18px">📁 Your Uploaded Files (<?= count($files) ?>)</h3>

    <?php if (count($files) > 0): ?>
      <!-- Desktop/Table view -->
      <div class="table-scroll" role="region" aria-label="Uploaded files table">
        <table class="files-table" role="table">
          <thead>
            <tr>
              <th style="width:48px">#</th>
              <th>Description</th>
              <th style="width:120px">Category</th>
              <th style="width:160px">Date</th>
              <th style="width:120px">File</th>
              <th style="width:180px">Actions</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($files as $i => $f):
              $idx = $i + 1;
              $desc = htmlspecialchars($f['description']);
              $cat = htmlspecialchars($f['category']);
              $date = htmlspecialchars($f['date']);
              $id = (int)$f['id'];
              $filename = htmlspecialchars($f['filename']);
            ?>
            <tr>
              <td><?= $idx ?></td>
              <td style="max-width:420px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"><?= $desc ?></td>
              <td><?= $cat ?></td>
              <td><?= $date ?></td>
              <td><a class="small-btn" href="?download=<?= $id ?>">Download</a></td>
              <td>
                <div class="action-row">
                  <a class="small-btn" href="secure_uploads/<?= $filename ?>">View</a>

                  <form method="post" onsubmit="return confirmDelete(this);" style="display:inline-block;margin:0">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($CSRF) ?>">
                    <input type="hidden" name="file_id" value="<?= $id ?>">
                    <button type="submit" name="delete_file" class="small-btn" style="background:#f97373;color:#fff;border:none">Delete</button>
                  </form>
                </div>
              </td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>

      <!-- Mobile: cards -->
      <div class="files-cards" aria-hidden="true">
        <?php foreach ($files as $i => $f):
          $idx = $i + 1;
          $desc = htmlspecialchars($f['description']);
          $cat = htmlspecialchars($f['category']);
          $date = htmlspecialchars($f['date']);
          $id = (int)$f['id'];
        ?>
        <article class="file-card" role="article" aria-label="<?= $desc ?>">
          <div class="card-row">
            <div class="card-meta">
              <div class="card-desc"><?= $desc ?></div>
              <div class="card-sub"><?= $cat ?> • <?= $date ?></div>
            </div>
            <div style="display:flex;gap:8px;align-items:center">
              <a class="small-btn" href="?download=<?= $id ?>">Download</a>
            </div>
          </div>
          <div class="card-actions">
            <form method="post" onsubmit="return confirmDelete(this);" style="width:100%;display:flex;gap:8px">
              <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($CSRF) ?>">
              <input type="hidden" name="file_id" value="<?= $id ?>">
              <button type="submit" name="delete_file" class="small-btn" style="flex:1;background:#f97373;color:#fff;border:none">Delete</button>
              <a class="small-btn" style="flex:1;text-align:center" href="secure_uploads/<?= $filename ?>">View</a>
            </form>
          </div>
        </article>
        <?php endforeach; ?>
      </div>

    <?php else: ?>
      <p style="color:var(--muted)">No files uploaded yet.</p>
    <?php endif; ?>
</div>

<script src="file.js?v<?php echo time();?>">

</script>

</body>
</html>
