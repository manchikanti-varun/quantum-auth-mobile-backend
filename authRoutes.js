/**
 * Auth routes – /api/auth (register, login, profile, backup OTP).
 */
const express = require('express');
const { register, login, getLoginStatus, loginWithOtp, setupBackupOtp, getLoginHistory, getMe, changePassword, googleAuth } = require('./authController');
const { authMiddleware } = require('./authMiddleware');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/google', googleAuth);
router.get('/login-status', getLoginStatus);
router.post('/login-with-otp', loginWithOtp);
router.post('/setup-backup-otp', authMiddleware, setupBackupOtp);
router.get('/login-history', authMiddleware, getLoginHistory);
router.get('/me', authMiddleware, getMe);
router.post('/change-password', authMiddleware, changePassword);

module.exports = router;

