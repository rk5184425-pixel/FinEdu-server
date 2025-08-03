const OTP = require('../models/OTP');
const User = require('../models/User');
const Profile = require('../models/Profile');
const { generateOTP } = require('../utils/otpGenerator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const emailsender = require('../utils/emailsender');
const accountCreationTemplate = require('../mail/accountCreationTemplate');

// @desc    Send OTP for registration
// @route   POST /api/auth/send-otp
// @access  Public
exports.sendOTP = async (req, res) => {
  try {
    console.log('📝 Sending OTP for registration...');
    const { email } = req.body;
    
    console.log(`📝 Email: ${email}`);
    
    if (await User.findOne({ email })) {
      console.log('❌ User already exists:', email);
      return res.status(401).json({
        success: false,
        message: "User is already registered"
      });
    }

    let otp;
    let existingOTP;

    do {
      otp = generateOTP(4);
      existingOTP = await OTP.findOne({ otp });
    } while (existingOTP);

    console.log(`📝 Generated OTP: ${otp}`);

    const otpObj = await OTP.create({ email, otp });
    console.log('✅ OTP created and saved');

    // Send OTP email
    console.log('📝 Sending OTP email...');
    const emailSent = await emailsender(
      email, 
      'FinEduGuard - Email Verification OTP',
      `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
          <h1 style="color: white; margin: 0;">FinEduGuard</h1>
          <p style="color: white; margin: 5px 0;">Secure Financial Education</p>
        </div>
        
        <div style="padding: 30px; background: #f8f9fa;">
          <h2 style="color: #151717; margin-bottom: 20px;">Email Verification</h2>
          <p style="color: #666; line-height: 1.6;">
            Thank you for signing up with FinEduGuard! To complete your registration, please use the verification code below:
          </p>
          
          <div style="background: #151717; color: white; padding: 20px; text-align: center; margin: 30px 0; border-radius: 10px;">
            <h1 style="font-size: 32px; margin: 0; letter-spacing: 5px;">${otp}</h1>
          </div>
          
          <p style="color: #666; line-height: 1.6;">
            This code will expire in 10 minutes. If you didn't request this verification, please ignore this email.
          </p>
          
          <p style="color: #666; line-height: 1.6;">
            Best regards,<br>
            The FinEduGuard Team
          </p>
        </div>
        
        <div style="background: #151717; color: white; padding: 20px; text-align: center;">
          <p style="margin: 0; font-size: 12px;">
            © 2024 FinEduGuard. All rights reserved.
          </p>
        </div>
      </div>
      `
    );

    if (!emailSent) {
      console.log('❌ Failed to send OTP email');
      return res.status(500).json({
        success: false,
        message: 'Failed to send OTP email'
      });
    }

    console.log('✅ OTP sent successfully');
    res.status(200).json({
      success: true,
      data: otpObj.otp,
      message: 'OTP sent successfully',
    });

  } catch (error) {
    console.error('❌ Send OTP error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send otp. Please try again',
      error: error.message,
    });
  }
};

// @desc    Sign up user
// @route   POST /api/auth/signup
// @access  Public
exports.signUp = async (req, res) => {
  try {
    console.log('📝 [SIGNUP] Step 1: Received request body:', req.body);
    let { firstName, lastName, email, password, otp } = req.body;

    if (!(firstName && lastName && email && password && otp)) {
      console.log('❌ [SIGNUP] Step 2: Missing required fields:', { firstName, lastName, email, password, otp });
      return res.status(403).json({
        success: false,
        message: "Some fields are missing"
      });
    }

    console.log(`📝 [SIGNUP] Step 3: Attempting signup for user: ${firstName} ${lastName} (${email})`);

    // Find the most recent OTP for the email
    const recentOtp = await OTP.find({ email }).sort({ createdAt: -1 }).limit(1);
    console.log('[SIGNUP] Step 4: Most recent OTP found:', recentOtp.length > 0 ? recentOtp[0].otp : null);

    if (recentOtp.length === 0 || otp !== recentOtp[0].otp) {
      console.log('❌ [SIGNUP] Step 5: Invalid OTP. Provided:', otp, 'Expected:', recentOtp.length > 0 ? recentOtp[0].otp : null);
      return res.status(400).json({
        success: false,
        message: 'OTP is not valid. Please try again'
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log('❌ [SIGNUP] Step 6: User already exists:', email);
      return res.status(400).json({
        success: false,
        message: 'User already exist. Please sign in to continue'
      });
    }

    console.log('[SIGNUP] Step 7: Creating user profile...');
    const profile = await Profile.create({});

    console.log('[SIGNUP] Step 8: Creating user...');
    const user = await User.create({
      firstName,
      lastName,
      email,
      password,
      profile: profile._id,
      avatar: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName}%20${lastName}`,
    });
    console.log('[SIGNUP] Step 9: User created successfully:', user._id);

    // Send welcome email
    console.log('[SIGNUP] Step 10: Sending welcome email...');
    const emailSent = await emailsender(
      email, 
      `Your account created successfully for ${firstName} ${lastName}`, 
      accountCreationTemplate(firstName + ' ' + lastName)
    );

    if (!emailSent) {
      console.log('[SIGNUP] Step 11: Failed to send welcome email, but user created successfully');
    }

    // Clear the used OTP
    await OTP.deleteOne({ _id: recentOtp[0]._id });
    console.log('[SIGNUP] Step 12: OTP deleted after use');

    console.log('[SIGNUP] Step 13: Signup completed successfully');
    sendTokenResponse(res, user, 201);

  } catch (error) {
    console.error('❌ Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to sign up. Please try again',
      error: error.message,
    });
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res, next) => {
  try {
    console.log('📝 User login started...');
    const email = req.body.email;
    const password = req.body.password;

    if (!email || !password) {
      console.log('❌ Missing email or password');
      return res.status(403).json({
        success: false,
        message: "Some fields are missing"
      });
    }

    console.log(`📝 Login attempt for: ${email}`);

    const user = await User.findOne({ email }).select('+password');

    if (!user) {
      console.log('❌ User not found:', email);
      return res.status(400).json({
        success: false,
        message: "Invalid credentials"
      });
    }

    if (!(await bcrypt.compare(password, user.password))) {
      console.log('❌ Invalid password for:', email);
      return res.status(400).json({
        success: false,
        message: "Invalid credentials"
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    console.log('✅ Login successful for:', email);
    sendTokenResponse(res, user, 200);

  } catch (err) {
    console.error('❌ Login error:', err);
    return res.status(500).json({
      success: false,
      message: "Login failed. Please try again"
    });
  }
};

// @desc    Logout user
// @route   POST /api/auth/logout
// @access  Private
exports.logOut = async (req, res, next) => {
  try {
    res
      .cookie('token', 'none', {
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true,
      })
      .status(200)
      .json({
        success: true,
        data: {},
      });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Failed to log out. Please try again"
    });
  }
};

// @desc    Forgot password
// @route   POST /api/auth/forgot-password
// @access  Public
exports.forgotPassword = async (req, res) => {
  try {
    console.log('📝 Forgot password started...');
    const { email } = req.body;

    // Find the user by email
    let user = await User.findOne({ email });
    if (!user) {
      console.log('❌ User not found for password reset:', email);
      return res.status(400).json({
        success: false,
        message: "Email not found. Please enter a valid email"
      });
    }

    console.log('📝 Generating reset token for:', email);

    // Generate OTP for password reset
    let otp;
    let existingOTP;
    do {
      otp = generateOTP(4);
      existingOTP = await OTP.findOne({ otp });
    } while (existingOTP);

    // Save OTP for password reset
    await OTP.create({ email, otp });

    // Send OTP email
    console.log('📝 Sending password reset OTP email...');
    const emailSent = await emailsender(
      user.email,
      `Password Reset OTP for ${user.firstName} ${user.lastName}`,
      `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
          <h1 style="color: white; margin: 0;">FinEduGuard</h1>
          <p style="color: white; margin: 5px 0;">Secure Financial Education</p>
        </div>
        <div style="padding: 30px; background: #f8f9fa;">
          <h2 style="color: #151717; margin-bottom: 20px;">Password Reset OTP</h2>
          <p style="color: #666; line-height: 1.6;">
            Hi ${user.firstName} ${user.lastName},
          </p>
          <p style="color: #666; line-height: 1.6;">
            You are receiving this email because you (or someone else) has requested to reset your FinEduGuard account password.
          </p>
          <div style="background: #151717; color: white; padding: 20px; text-align: center; margin: 30px 0; border-radius: 10px;">
            <h1 style="font-size: 32px; margin: 0; letter-spacing: 5px;">${otp}</h1>
          </div>
          <p style="color: #666; line-height: 1.6;">
            Please enter this OTP in the FinEduGuard app to reset your password. This code will expire in 10 minutes.
          </p>
          <p style="color: #666; line-height: 1.6;">
            If you didn't request this reset, please ignore this email and your password will remain unchanged.
          </p>
          <p style="color: #666; line-height: 1.6;">
            Best regards,<br>
            The FinEduGuard Team
          </p>
        </div>
        <div style="background: #151717; color: white; padding: 20px; text-align: center;">
          <p style="margin: 0; font-size: 12px;">
            © 2024 FinEduGuard. All rights reserved.
          </p>
        </div>
      </div>
      `
    );

    if (!emailSent) {
      console.log('❌ Failed to send password reset OTP email');
      return res.status(500).json({
        success: false,
        message: 'Failed to send password reset OTP email'
      });
    }

    console.log('✅ Password reset OTP email sent successfully');
    return res.status(200).json({
      success: true,
      message: "Password reset OTP email sent successfully."
    });

  } catch (error) {
    console.error('❌ Forgot password error:', error);
    return res.status(500).json({
      success: false,
      message: "Failed to process password reset request. Please try again.",
      error: error.message
    });
  }
};

// @desc    Reset password
// @route   POST /api/auth/reset-password
// @access  Public
exports.resetPassword = async (req, res) => {
  try {
    console.log('📝 Reset password started...');
    const { password, resetToken } = req.body;
    
    if (!(password && resetToken)) {
      console.log('❌ Missing password or reset token');
      return res.status(400).json({
        success: false,
        message: 'Some fields are missing',
      });
    }

    // Get hashed token
    const resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    let user = await User.findOne({ resetPasswordToken });
    if (!user) {
      console.log('❌ Invalid reset token');
      return res.status(400).json({
        success: false,
        message: 'Invalid request',
      });
    }

    if (Date.now() > user.resetPasswordExpire) {
      console.log('❌ Reset token expired');
      return res.status(400).json({
        success: false,
        message: 'Token is expired. Please regenerate your token',
      });
    }

    console.log('📝 Updating password for:', user.email);

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);
    user = await User.findByIdAndUpdate(
      user._id,
      {
        password: hashedPassword,
        resetPasswordToken: undefined,
        resetPasswordExpire: undefined,
      },
      { new: true }
    );

    // Send email to user confirming password reset
    try {
      console.log('📝 Sending password reset confirmation email...');
      await emailsender(
        user.email,
        `Password has been reset successfully for ${user.firstName} ${user.lastName}`,
        `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">FinEduGuard</h1>
            <p style="color: white; margin: 5px 0;">Secure Financial Education</p>
          </div>
          
          <div style="padding: 30px; background: #f8f9fa;">
            <h2 style="color: #151717; margin-bottom: 20px;">Password Reset Successful</h2>
            <p style="color: #666; line-height: 1.6;">
              Hi ${user.firstName} ${user.lastName},
            </p>
            <p style="color: #666; line-height: 1.6;">
              Your password has been reset successfully. Thanks for being with us.
            </p>
            
            <div style="background: #151717; color: white; padding: 20px; text-align: center; margin: 30px 0; border-radius: 10px;">
              <h3 style="margin: 0;">✅ Password Reset Complete</h3>
              <p style="margin: 10px 0 0 0; font-size: 14px;">
                Your account is now secure with your new password.
              </p>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${process.env.FRONTEND_SITE || 'http://localhost:3000'}" 
                 style="background: #151717; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                Visit FinEduGuard
              </a>
            </div>
            
            <p style="color: #666; line-height: 1.6;">
              If you didn't request this reset, please contact our support team immediately.
            </p>
            
            <p style="color: #666; line-height: 1.6;">
              Best regards,<br>
              The FinEduGuard Team
            </p>
          </div>
          
          <div style="background: #151717; color: white; padding: 20px; text-align: center;">
            <p style="margin: 0; font-size: 12px;">
              © 2024 FinEduGuard. All rights reserved.
            </p>
          </div>
        </div>
        `
      );
    } catch (err) {
      console.log('⚠️ Failed to send reset confirmation email, but password was reset');
    }

    console.log('✅ Password reset successful for:', user.email);
    // Send response with token
    sendTokenResponse(res, user, 200);
  } catch (err) {
    console.error('❌ Reset password error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to reset password. Please try again',
    });
  }
};

// @desc    Get current user
// @route   GET /api/auth/me
// @access  Private
const getMe = async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        user: req.user
      }
    });
  } catch (error) {
    console.error('Get me error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// Helper function to send token response
const sendTokenResponse = async (res, user, statusCode) => {
  const token = jwt.sign(
    {
      id: user._id,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE }
  );

  const options = {
    expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000),
    httpOnly: true,
  };

  res.cookie('token', token, options).status(statusCode).json({
    success: true,
    user,
    token,
  });
};

module.exports = {
  sendOTP: exports.sendOTP,
  signUp: exports.signUp,
  login: exports.login,
  logOut: exports.logOut,
  forgotPassword: exports.forgotPassword,
  resetPassword: exports.resetPassword,
  getMe
}; 