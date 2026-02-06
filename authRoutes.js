const express = require('express');
const { register, login, getLoginStatus, loginWithOtp, setupBackupOtp } = require('./authController');
const { authMiddleware } = require('./authMiddleware');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/login-status', getLoginStatus);
router.post('/login-with-otp', loginWithOtp);
router.post('/setup-backup-otp', authMiddleware, setupBackupOtp);

module.exports = router;

