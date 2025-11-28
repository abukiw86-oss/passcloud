<?php
require_once 'db.php';

$tables = ['users', 'passwords', 'security_logs'];

foreach ($tables as $table) {
    $query = "ALTER TABLE $table CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci";
    if (mysqli_query($conn, $query)) {
        echo "Fixed collation for $table<br>";
    } else {
        echo "Error fixing $table: " . mysqli_error($conn) . "<br>";
    }
}

echo "Collation fix complete!";
?>