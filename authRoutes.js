const express = require('express');
const { register, login, getLoginStatus, loginWithOtp, setupBackupOtp, getLoginHistory } = require('./authController');
const { authMiddleware } = require('./authMiddleware');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/login-status', getLoginStatus);
router.post('/login-with-otp', loginWithOtp);
router.post('/setup-backup-otp', authMiddleware, setupBackupOtp);
router.get('/login-history', authMiddleware, getLoginHistory);

module.exports = router;

