<?php
http_response_code(404);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Page Not Found - PassCloud</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            text-align: center; 
            padding: 50px; 
            background: #051e37ff;
        }
        .container { 
            max-width: 600px; 
            margin: 0 auto; 
            background: blue;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .btn { 
            display: inline-block; 
            padding: 12px 24px; 
            background: #007bff; 
            color: white; 
            text-decoration: none; 
            border-radius: 5px;
            margin: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Page Not Found</h1>
        <p>The page you're looking for doesn't exist in PassCloud.</p>
        <p><strong>Requested URL:</strong> <?php echo htmlspecialchars($_SERVER['REQUEST_URI']); ?></p>
        
        <div>
            <a href="/passcloud/" class="btn">🏠 Go to PassCloud Home</a>
            <a href="javascript:history.back()" class="btn" style="background: #6c757d;">↩ Go Back</a>
        </div>
    </div>
</body>
</html>