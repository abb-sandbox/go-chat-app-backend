package handlers

const verification_success = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Activated</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 90%; }
        .success-icon { width: 80px; height: 80px; background-color: #4BB543; border-radius: 50%; display: flex; justify-content: center; align-items: center; margin: 0 auto 20px; }
        .checkmark { color: white; font-size: 50px; font-weight: bold; }
        h1 { color: #333; margin-bottom: 10px; font-size: 24px; }
        p { color: #666; line-height: 1.5; margin-bottom: 25px; }
        .btn { background-color: #4BB543; color: white; padding: 12px 25px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block; transition: background 0.3s; }
        .btn:hover { background-color: #3e9e37; }
    </style>
</head>
<body>
    <div class="card">
        <div class="success-icon">
            <span class="checkmark">&check;</span>
        </div>
        <h1>Account Activated!</h1>
        <p>Your email has been successfully verified. You can now log in and start using the app.</p>
        <a href="myapp://login" class="btn">Open App</a>
    </div>
</body>
</html>
`
