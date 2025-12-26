/**
 * Authentication Utility
 * 
 * Shared utility functions for client-side authentication checks.
 * Provides methods to check token presence, decode JWT payload, and verify roles.
 */

/**
 * Cleans up legacy authentication data from localStorage
 */
function cleanupLegacyAuth() {
    localStorage.removeItem('aiProjectControlTowerAuth_v2');
}

/**
 * Checks if required authentication tokens are present in localStorage
 * @returns {Object} Object with hasAccessToken and hasUserData boolean properties
 */
function checkTokenPresence() {
    const accessToken = localStorage.getItem('access_token');
    const userData = localStorage.getItem('user_data');
    return {
        hasAccessToken: !!accessToken,
        hasUserData: !!userData,
        accessToken: accessToken,
        userData: userData
    };
}

/**
 * Decodes JWT token payload (base64url decoding)
 * @param {string} token - JWT access token
 * @returns {Object} Decoded JWT payload
 * @throws {Error} If token format is invalid or decoding fails
 */
function decodeJWTPayload(token) {
    if (!token || typeof token !== 'string') {
        throw new Error('Invalid token: token is required and must be a string');
    }
    
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid token format: JWT must have 3 parts separated by dots');
    }
    
    try {
        // Handle base64url decoding (JWT uses base64url, not base64)
        let payload = parts[1];
        // Replace base64url characters
        payload = payload.replace(/-/g, '+').replace(/_/g, '/');
        // Add padding if needed
        while (payload.length % 4) {
            payload += '=';
        }
        const decoded = JSON.parse(atob(payload));
        return decoded;
    } catch (e) {
        throw new Error(`Failed to decode JWT payload: ${e.message}`);
    }
}

/**
 * Extracts user role from JWT token
 * @param {string} token - JWT access token
 * @returns {string|null} User role or null if not found
 */
function getUserRole(token) {
    try {
        const decoded = decodeJWTPayload(token);
        return decoded.role || null;
    } catch (e) {
        console.error('Error extracting role from token:', e);
        return null;
    }
}

/**
 * Verifies authentication by checking token presence
 * Redirects to landing page if tokens are missing
 * @param {string} redirectPath - Path to redirect to if authentication fails (default: '/')
 * @param {boolean} showContent - Whether to show content after auth check passes (default: false)
 * @returns {boolean} True if authenticated, false if redirected
 */
function verifyAuth(redirectPath = '/', showContent = false) {
    const tokenCheck = checkTokenPresence();
    
    if (!tokenCheck.hasAccessToken || !tokenCheck.hasUserData) {
        // Log authentication failure for debugging
        console.warn('Authentication check failed: Missing tokens', {
            hasAccessToken: tokenCheck.hasAccessToken,
            hasUserData: tokenCheck.hasUserData
        });
        // Clean up old auth format if it exists
        cleanupLegacyAuth();
        console.log('Redirecting to landing page due to missing authentication tokens');
        window.location.href = redirectPath;
        return false;
    }
    
    // Authentication check passed
    if (showContent) {
        document.body.classList.remove('auth-check-pending');
    }
    console.log('Authentication check passed');
    return true;
}

/**
 * Verifies user has required role
 * Redirects if role check fails
 * @param {string|string[]} requiredRole - Required role(s) to check
 * @param {string} redirectPath - Path to redirect to if role check fails (default: '/dashboard')
 * @returns {boolean} True if authorized, false if redirected
 */
function verifyRole(requiredRole, redirectPath = '/dashboard') {
    const tokenCheck = checkTokenPresence();
    
    // First check if tokens exist
    if (!tokenCheck.hasAccessToken || !tokenCheck.hasUserData) {
        cleanupLegacyAuth();
        window.location.href = '/';
        return false;
    }
    
    // Parse JWT token to verify role
    try {
        const role = getUserRole(tokenCheck.accessToken);
        
        if (!role) {
            console.error('Role not found in token');
            window.location.href = redirectPath;
            return false;
        }
        
        // Check if user has required role
        const requiredRoles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
        const hasRequiredRole = requiredRoles.includes(role);
        
        if (!hasRequiredRole) {
            console.warn(`Role check failed: Required ${requiredRoles.join(' or ')}, but user has ${role}`);
            window.location.href = redirectPath;
            return false;
        }
        
        // Role check passed
        console.log(`Role check passed: User has ${role}`);
        return true;
    } catch (e) {
        console.error('Error parsing auth data:', e);
        window.location.href = redirectPath;
        return false;
    }
}


