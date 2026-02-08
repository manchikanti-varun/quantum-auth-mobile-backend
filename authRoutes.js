/**
 * Auth routes – /api/auth (register, login, profile, backup OTP).
 */
const express = require('express');
const { register, login, getLoginStatus, loginWithOtp, setupBackupOtp, getLoginHistory, deleteLoginHistoryEntry, getMe, updatePreferences, changePassword, forgotPassword, requestPasswordResetCode } = require('./authController');
const { authMiddleware } = require('./authMiddleware');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/login-status', getLoginStatus);
router.post('/login-with-otp', loginWithOtp);
router.post('/setup-backup-otp', authMiddleware, setupBackupOtp);
router.get('/login-history', authMiddleware, getLoginHistory);
router.delete('/login-history/:id', authMiddleware, deleteLoginHistoryEntry);
router.get('/me', authMiddleware, getMe);
router.patch('/preferences', authMiddleware, updatePreferences);
router.post('/change-password', authMiddleware, changePassword);
router.post('/forgot-password', forgotPassword);
router.post('/request-password-reset-code', authMiddleware, requestPasswordResetCode);

module.exports = router;

