<?php
// Database configuration
$db = new PDO('sqlite:banking.db');

// Create tables if they don't exist
$db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    balance REAL DEFAULT 0
)");

// Function to register a new user
function registerUser($username, $password) {
    global $db;
    $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->execute([$username, password_hash($password, PASSWORD_BCRYPT)]);
}

// Function to login a user
function loginUser($username, $password) {
    global $db;
    $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password'])) {
        return $user;
    } else {
        return false;
    }
}

// Function to get user balance
function getBalance($userId) {
    global $db;
    $stmt = $db->prepare("SELECT balance FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $balance = $stmt->fetchColumn();
    return $balance;
}

// Function to deposit money
function depositMoney($userId, $amount) {
    global $db;
    $stmt = $db->prepare("UPDATE users SET balance = balance + ? WHERE id = ?");
    $stmt->execute([$amount, $userId]);
}

// Function to withdraw money
function withdrawMoney($userId, $amount) {
    global $db;
    $stmt = $db->prepare("UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?");
    $stmt->execute([$amount, $userId, $amount]);
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['register'])) {
        registerUser($_POST['username'], $_POST['password']);
        echo "User registered successfully!";
    } elseif (isset($_POST['login'])) {
        $user = loginUser($_POST['username'], $_POST['password']);
        if ($user) {
            session_start();
            $_SESSION['user_id'] = $user['id'];
            echo "Login successful!";
        } else {
            echo "Invalid username or password!";
        }
    } elseif (isset($_POST['deposit'])) {
        session_start();
        if (isset($_SESSION['user_id'])) {
            depositMoney($_SESSION['user_id'], $_POST['amount']);
            echo "Deposit successful!";
        } else {
            echo "Please login first!";
        }
    } elseif (isset($_POST['withdraw'])) {
        session_start();
        if (isset($_SESSION['user_id'])) {
            withdrawMoney($_SESSION['user_id'], $_POST['amount']);
            echo "Withdrawal successful!";
        } else {
            echo "Please login first!";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Banking Platform</title>
</head>
<body>
    <h1>Banking Platform</h1>

    <?php if (!isset($_SESSION['user_id'])): ?>
        <h2>Register</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" name="register">Register</button>
        </form>

        <h2>Login</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" name="login">Login</button>
        </form>
    <?php else: ?>
        <h2>Welcome, <?php echo $_SESSION['user_id']; ?>!</h2>
        <p>Your balance: <?php echo getBalance($_SESSION['user_id']); ?></p>

        <h2>Deposit</h2>
        <form method="post">
            <input type="number" name="amount" placeholder="Amount">
            <button type="submit" name="deposit">Deposit</button>
        </form>

        <h2>Withdraw</h2>
        <form method="post">
            <input type="number" name="amount" placeholder="Amount" required>
            <button type="submit" name="withdraw">Withdraw</button>
        </form>

        <h2>Logout</h2>
        <form method="post">
            <button type="submit" name="logout">Logout</button>
        </form>
    <?php endif; ?>

    <?php
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        if (isset($_POST['logout'])) {
            session_start();
            session_destroy();
            echo "You have been logged out!";
        }
    }
    ?>
</body>
</html>

