const express = require('express');
const { register, login, getLoginStatus, loginWithOtp, setupBackupOtp, getLoginHistory, getMe, changePassword } = require('./authController');
const { authMiddleware } = require('./authMiddleware');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/login-status', getLoginStatus);
router.post('/login-with-otp', loginWithOtp);
router.post('/setup-backup-otp', authMiddleware, setupBackupOtp);
router.get('/login-history', authMiddleware, getLoginHistory);
router.get('/me', authMiddleware, getMe);
router.post('/change-password', authMiddleware, changePassword);

module.exports = router;

