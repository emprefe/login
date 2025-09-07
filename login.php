<?php
// user_manager/login/post_get_login.php
// Handles login form submission with remember_me using dedicated table

// Ensure secure access
if (!defined('SECURE_ACCESS')) {
    header('HTTP/1.0 403 Forbidden');
    exit('Direct access not allowed.');
}

// Include the centralized logging functionality
include_once "user_manager/security/logging.php";

// Default response
$response = [
    'status' => 'error',
    'message' => 'An unknown error occurred. Please try again.'
];

try {
    // Basic validations
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_POST['request']) || $_POST['request'] !== 'login') {
        throw new Exception("Invalid request method or type");
    }
    
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        throw new Exception("Security token validation failed");
    }
    
    // Check required fields
    if (!isset($_POST['username']) || !isset($_POST['password']) || 
        trim($_POST['username']) === '' || trim($_POST['password']) === '') {
        throw new Exception("Please enter both username and password");
    }
    
    // Sanitize inputs
    $username = sanitize($_POST['username']);
    $password = $_POST['password']; // Not sanitized for password verification
    $remember = isset($_POST['remember_me']) && $_POST['remember_me'] === 'on';
    
    // Get user from database
    $stmt = $conn->prepare("
        SELECT id, username, email, password, first_name, last_name, status, is_admin
        FROM users 
        WHERE username = ?
    ");
    
    if (!$stmt) {
        throw new Exception("Database preparation error");
    }
    
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        // User not found - But don't reveal this information
        throw new Exception("Invalid username or password");
    }
    
    $user = $result->fetch_assoc();
    $stmt->close();
    
    // Check if account is inactive/pending verification
    if ($user['status'] === 'inactive') {
        throw new Exception("Your account is not activated. Please check your email for the verification link.");
    }
    
    // Check if account is suspended
    if ($user['status'] === 'suspended') {
        throw new Exception("Your account has been suspended. Please contact support for assistance.");
    }
    
    // Verify password
    if (!password_verify($password, $user['password'])) {
        // Log failed login attempt
        $notes = "Failed login attempt for username: " . $username;
        logSecurityEvent($conn, $user['id'], 'failed_login', null, $notes);
        
        throw new Exception("Invalid username or password");
    }
    
    // Login successful
    
    // Set session variables
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['first_name'] = $user['first_name'];
    $_SESSION['last_name'] = $user['last_name'];
    $_SESSION['email'] = $user['email'];
    $_SESSION['status'] = $user['status'];
    
    // Store IP and user agent for session hijacking protection
    $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
    $_SESSION['last_activity'] = time();
    $_SESSION['last_regeneration'] = time();
    
// Get user roles with IDs and names
$rolesQuery = "
    SELECT r.id, r.name
    FROM roles r
    JOIN user_roles ur ON r.id = ur.role_id
    WHERE ur.user_id = ?
";

$rolesStmt = $conn->prepare($rolesQuery);
$rolesStmt->bind_param("i", $user['id']);
$rolesStmt->execute();
$rolesResult = $rolesStmt->get_result();

$roles = [];
$role_ids = [];
$isAdmin = false;

while ($roleRow = $rolesResult->fetch_assoc()) {
    $roles[] = $roleRow['name'];
    $role_ids[] = $roleRow['id'];
    
    // Check if the user has the Admin role
    if ($roleRow['id'] === '1') {
        $isAdmin = true;
    }
}

$_SESSION['roles'] = $roles;
$_SESSION['roles_ids'] = $role_ids;    
    // Set is_admin flag based on roles and also use the DB field as a backup check
    $_SESSION['is_admin'] = $isAdmin || (bool)$user['is_admin']; 
    
    // Log admin status for debugging
    error_log("Login - User ID: " . $user['id'] . ", Username: " . $user['username'] . 
              ", is_admin flag: " . ($_SESSION['is_admin'] ? 'true' : 'false') . 
              ", Role-based admin: " . ($isAdmin ? 'true' : 'false') . 
              ", DB admin field: " . ($user['is_admin'] ? 'true' : 'false'));
    
    $rolesStmt->close();
    
    // Ensure the is_admin field in database is synchronized with role-based status
    if ($isAdmin && !$user['is_admin']) {
        try {
            $updateAdminStmt = $conn->prepare("UPDATE users SET is_admin = 1 WHERE id = ?");
            $updateAdminStmt->bind_param("i", $user['id']);
            $updateAdminStmt->execute();
            $updateAdminStmt->close();
            error_log("Updated is_admin flag to 1 in database for user ID: " . $user['id']);
        } catch (Exception $e) {
            error_log("Error updating admin flag: " . $e->getMessage());
        }
    }
    
    // Handle Remember Me
    if ($remember) {
        // Get settings for remember_me lifetime (default 30 days)
        $rememberMeLifetime = 30;
        
        // Try to get from system settings if available
        $settingsStmt = $conn->prepare("SELECT setting_value FROM system_settings WHERE setting_key = 'remember_me_lifetime'");
        if ($settingsStmt) {
            $settingsStmt->execute();
            $settingResult = $settingsStmt->get_result();
            if ($row = $settingResult->fetch_assoc()) {
                $rememberMeLifetime = (int)$row['setting_value'];
            }
            $settingsStmt->close();
        }
        
        // Generate secure tokens
        $selector = bin2hex(random_bytes(12));
        $validator = bin2hex(random_bytes(32));
        
        // Hash the validator for database storage
        $hashedValidator = password_hash($validator, PASSWORD_DEFAULT);
        
        // Set expiration based on settings
        $expires = new DateTime();
        $expires->add(new DateInterval('P' . $rememberMeLifetime . 'D'));
        $expiresStr = $expires->format('Y-m-d H:i:s');
        
        // Get client information
        $ipAddress = $_SERVER['REMOTE_ADDR'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'];
        
        // Insert new remember_me token
        $rememberStmt = $conn->prepare("
            INSERT INTO remember_me 
            (user_id, selector, token, expires, ip_address, user_agent) 
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        
        $rememberStmt->bind_param("isssss", 
            $user['id'], 
            $selector, 
            $hashedValidator, 
            $expiresStr, 
            $ipAddress, 
            $userAgent
        );
        
        $rememberStmt->execute();
        $rememberStmt->close();
        
        // Set cookie based on lifetime setting
        $cookieValue = $selector . ':' . $validator;
        setcookie(
            'remember_me',
            $cookieValue,
            time() + (86400 * $rememberMeLifetime), // days in seconds
            '/',
            '',
            true,  // secure flag
            true   // httpOnly flag
        );
    } else {
        // If not using remember me, ensure any existing cookie is cleared
        if (isset($_COOKIE['remember_me'])) {
            setcookie('remember_me', '', time() - 3600, '/', '', true, true);
        }
    }
    
    // Log successful login with notes
    $notes = "User logged in" . ($remember ? " with 'Remember Me' enabled" : "");
    $notes .= ". Roles: " . implode(", ", $roles);
    
    logSecurityEvent($conn, $user['id'], 'login', null, $notes);
    
    // Update last login timestamp
    $updateStmt = $conn->prepare("
        UPDATE users 
        SET last_login = NOW() 
        WHERE id = ?
    ");
    
    $updateStmt->bind_param("i", $user['id']);
    $updateStmt->execute();
    $updateStmt->close();
    
    // Generate new CSRF token
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    
    // Success response
    $response = [
        'status' => 'success',
        'message' => 'Login successful!',
        'redirect' => 'index.php?page=dashboard'
    ];
    
} catch (Exception $e) {
    // Log the error
    error_log("Login error: " . $e->getMessage());
    
    // Set error response
    $response = [
        'status' => 'error',
        'message' => $e->getMessage()
    ];
}

// Return response
header('Content-Type: application/json');
echo json_encode($response);
exit;
?>
