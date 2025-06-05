const express = require('express');
const router = express.Router();
const auth = require('../controllers/authControllers');

router.post('/signup', auth.signup);
router.post('/verify-otp', auth.verifyOtp);
router.post('/login', auth.login);
router.post('/forgot-password', auth.forgotPassword);
router.post('/reset-password', auth.resetPassword);

module.exports = router;
