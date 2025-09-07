<?php
// user_manager/login/index.php 
// Ensure secure access
if (!defined('SECURE_ACCESS')) {
    header('HTTP/1.0 403 Forbidden');
    exit('Direct access not allowed.');
}

// Include CSRF protection
include_once "user_manager/security/CSRF_check.php";

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];
?>


    <div class="form_wrapper_small" id="login-wrapper">
        <div class="form_header">
            <h2>Login</h2>
        </div>
        
        <div class="form_body_small">
            <form id="login-form" method="post">
                <!-- CSRF token -->
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <input type="hidden" name="request" value="login">
                
                <div class="form_group">
                    <label for="username">Username</label>
                    <input type="text" name="username" id="username" class="w_100" required>
                </div>
                
                <div class="form_group">
                    <label for="password">Password</label>
                    <input type="password" name="password" id="password" class="w_100" required>
                </div>
                
    <div class="form_group">
        <label for="remember_me" style="display: inline-flex; align-items: center; gap: 8px; white-space: nowrap;">
            <input type="checkbox" name="remember_me" id="remember_me" style="margin: 0 5px;">

            Remember Me
        </label>
    </div>
                
                <div class="form_group mt_3">
                    <button type="button" id="login-button" class="btn w_100">Login</button>
                </div>
                
                <div class="mt_2 mb_2 text_center">
                    <a class="link" href="index.php?page=forgot_password">Forgot Password?</a>
                    <span style="margin: 0 8px;">|</span>
                    <a class="link" href="index.php?page=register">Create Account</a>
                </div>
            </form>
        </div>
    </div>
