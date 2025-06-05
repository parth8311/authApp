const User = require('../models/User');
const Otp = require('../models/Otp');
const bcrypt = require('bcryptjs');
const sendEmail = require('../utils/sendEmail');
const jwt = require('jsonwebtoken');

//SignUp

exports.signup = async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;

    // required fields 
    if (
      ![name, email, password, phone].every(field => typeof field === 'string' && field.trim() !== '')
    ) {
      return res.status(400).json({ msg: 'All fields are required and must be non-empty strings' });
    }

    // Name validation 
    const nameRegex = /^[a-zA-Z ]{2,30}$/;
    if (!nameRegex.test(name)) {
      return res.status(400).json({ msg: 'Name should contain only letters and spaces' });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ msg: 'Invalid email format' });
    }

    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ msg: 'Email already registered' });
    }

    // Password validation
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?#&_])[A-Za-z\d@$!%*?#&_]{8,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        msg: 'Password must be at least 8 characters long and include uppercase, lowercase, number, and special character'
      });
    }

    // Number Validation
    const phoneRegex = /^\+?\d{7,15}$/;
    if (!phoneRegex.test(phone)) {
      return res.status(400).json({ msg: 'Invalid phone number format' });
    }

    // Create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      phone
    });

    // Generate OTP
    const code = Math.floor(1000 + Math.random() * 9000).toString();
    await Otp.findOneAndDelete({ email }); // remove existing if any
    await Otp.create({
      email,
      code,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });

    await sendEmail(email, 'Verify your Email', `Your OTP code is: ${code}`);

    res.status(201).json({ msg: 'Signup successful. OTP sent to email.' });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ msg: 'Internal server error' });
  }
};

//VerifyOtp
exports.verifyOtp = async (req, res) => {
    const { email, code } = req.body;
  
    const otpRecord = await Otp.findOne({ email, code });
    if (!otpRecord) return res.status(400).json({ msg: 'Invalid OTP' });
    
  
    if (otpRecord.expiresAt < Date.now()) {
      await Otp.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({ msg: 'OTP expired' });
    }
  
    await User.updateOne({ email }, { isVerified: true });
    await Otp.deleteOne({ _id: otpRecord._id });
  
    res.json({ msg: 'Email verified successfully' });
};

//Login
exports.login = async (req, res) => {
    try {
      const { email, password } = req.body;
  
      // validation
      if (
        typeof email !== 'string' || !email.trim() ||
        typeof password !== 'string' || !password.trim()
      ) {
        return res.status(400).json({ msg: 'Email and password are required' });
      }
  
      // Email format check
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ msg: 'Invalid email format' });
      }
  
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ msg: 'User not found' });
      }
  
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ msg: 'Invalid credentials' });
      }
  
      if (!user.isVerified) {
        return res.status(403).json({ msg: 'Email not verified' });
      }
  
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '3d' });
      res.json({ token, user });
  
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ msg: 'Server error' });
    }
};

//ForgotPassword
exports.forgotPassword = async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: 'User not found' });
  
    const code = Math.floor(1000 + Math.random() * 9000).toString();
    await Otp.findOneAndDelete({ email });
    await Otp.create({
      email,
      code,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000)
    });
  
    await sendEmail(email, 'Password Reset OTP', `Your OTP is ${code}`);
    res.json({ msg: 'OTP sent to your email.' });
};

//ResetPassword
exports.resetPassword = async (req, res) => {
    try {
      const { email, code, newPassword } = req.body;
  
      // validation for missing or empty fields
      if (
        typeof email !== 'string' || !email.trim() ||
        typeof code !== 'string' || !code.trim() ||
        typeof newPassword !== 'string' || !newPassword.trim()
      ) {
        return res.status(400).json({
          msg: 'Email, OTP, and new password are required'
        });
      }
  
      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ msg: 'Invalid email format' });
      }
  
      // Validate password strength
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?#&_])[A-Za-z\d@$!%*?#&_]{8,}$/;
      if (!passwordRegex.test(newPassword)) {
        return res.status(400).json({
          msg: 'Password must be at least 8 characters and include uppercase, lowercase, number, and special character'
        });
      }
  
      // Check if OTP exists
      const otpRecord = await Otp.findOne({ email, code });
      if (!otpRecord) {
        return res.status(400).json({ msg: 'Invalid OTP' });
      }
  
      // Check if OTP expired
      if (otpRecord.expiresAt < Date.now()) {
        await Otp.deleteOne({ _id: otpRecord._id });
        return res.status(400).json({ msg: 'OTP expired' });
      }
  
      // Update password
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await User.updateOne({ email }, { password: hashedPassword });
  
      // Remove used OTP
      await Otp.deleteOne({ _id: otpRecord._id });
  
      res.json({ msg: 'Password reset successfully' });
  
    } catch (err) {
      console.error('Reset password error:', err);
      res.status(500).json({ msg: 'Server error' });
    }
};
  
  
  
  
  
