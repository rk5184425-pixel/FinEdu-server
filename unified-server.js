import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import axios from 'axios';
import fetch from 'node-fetch';
import { body, validationResult } from 'express-validator';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const app = express();

// Security middleware
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.'
  }
});
app.use('/api/', limiter);

// Body parser middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// CORS middleware
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://yourdomain.com'] 
    : ['http://localhost:3000', 'http://localhost:19006', '*'],
  credentials: true,
  methods: ["GET", "POST", "DELETE", "PUT", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// =============================================================================
// DATABASE MODELS
// =============================================================================

// OTP Schema
const otpSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true
  },
  otp: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 600 // OTP expires after 10 minutes
  }
});
otpSchema.index({ email: 1, createdAt: -1 });
const OTP = mongoose.model('OTP', otpSchema);

// Profile Schema
const profileSchema = new mongoose.Schema({
  firstName: { type: String, trim: true },
  lastName: { type: String, trim: true },
  email: { type: String, trim: true, lowercase: true },
  phoneNumber: { type: String, trim: true },
  dateOfBirth: { type: Date },
  gender: { type: String, enum: ['male', 'female', 'other', 'prefer-not-to-say'] },
  address: {
    street: String,
    city: String,
    state: String,
    country: String,
    zipCode: String
  },
  occupation: { type: String, trim: true },
  company: { type: String, trim: true },
  education: {
    degree: String,
    institution: String,
    graduationYear: Number
  },
  incomeRange: {
    type: String,
    enum: ['under-25k', '25k-50k', '50k-75k', '75k-100k', '100k-150k', 'over-150k']
  },
  investmentExperience: {
    type: String,
    enum: ['beginner', 'intermediate', 'advanced', 'expert']
  },
  interests: [{
    type: String,
    enum: ['stocks', 'bonds', 'crypto', 'real-estate', 'mutual-funds', 'etfs', 'retirement-planning', 'tax-planning', 'insurance']
  }],
  linkedin: String,
  twitter: String,
  website: String,
  isPublic: { type: Boolean, default: false },
  allowNotifications: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

profileSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});
const Profile = mongoose.model('Profile', profileSchema);

// User Schema
const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true,
    maxlength: [50, 'First name cannot be more than 50 characters']
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true,
    maxlength: [50, 'Last name cannot be more than 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  avatar: {
    type: String,
    default: function() {
      return `https://api.dicebear.com/5.x/initials/svg?seed=${this.firstName}%20${this.lastName}`;
    }
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  profile: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Profile'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  lastLogin: {
    type: Date,
    default: Date.now
  },
  loginHistory: [{
    timestamp: { type: Date, default: Date.now },
    ip: String,
    userAgent: String
  }]
}, {
  timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    throw new Error('Password comparison failed');
  }
};

// Generate password reset token
userSchema.methods.getResetPasswordToken = function() {
  const resetToken = crypto.randomBytes(20).toString('hex');
  this.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

const User = mongoose.model('User', userSchema);

// Document Schema
const documentSchema = new mongoose.Schema({
  filename: String,
  hash: String,
  walletAddress: String,
  timestamp: Number,
  size: Number,
  type: String,
});
const Document = mongoose.model('Document', documentSchema);

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

// OTP Generator
const generateOTP = (length = 4) => {
  const digits = '0123456789';
  let otp = '';
  for (let i = 0; i < length; i++) {
    otp += digits[Math.floor(Math.random() * digits.length)];
  }
  return otp;
};

// Email sender
const emailsender = async (email, subject, html) => {
  try {
    console.log('📧 Sending email...');
    console.log(`📧 To: ${email}`);
    console.log(`📧 Subject: ${subject}`);
    
    const transporter = nodemailer.createTransporter({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: `"${process.env.FROM_NAME}" <${process.env.FROM_EMAIL}>`,
      to: email,
      subject: subject,
      html: html
    };

    console.log('📤 Sending email...');
    const info = await transporter.sendMail(mailOptions);
    console.log('✅ Email sent successfully');
    console.log(`📧 Message ID: ${info.messageId}`);
    return true;
  } catch (error) {
    console.error('❌ Email sending failed:', error.message);
    console.error('📧 Full error:', error);
    return false;
  }
};

// Test email connection
const testEmailConnection = async () => {
  try {
    console.log('🔧 Testing email configuration...');
    const transporter = nodemailer.createTransporter({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
    
    await transporter.verify();
    console.log('✅ Email configuration is valid');
    return true;
  } catch (error) {
    console.error('❌ Email configuration test failed:', error.message);
    return false;
  }
};

// =============================================================================
// MIDDLEWARE
// =============================================================================

// Authentication middleware
const protect = async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await User.findById(decoded.id).select('-password');

      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'User not found'
        });
      }

      if (!req.user.isActive) {
        return res.status(401).json({
          success: false,
          message: 'Account is deactivated'
        });
      }

      next();
    } catch (error) {
      console.error('Token verification error:', error);
      return res.status(401).json({
        success: false,
        message: 'Not authorized, token failed'
      });
    }
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Not authorized, no token'
    });
  }
};

// Validation middleware
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array()
    });
  }
  next();
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

// =============================================================================
// PHISHING DETECTION UTILITIES
// =============================================================================

const VT_API_KEY = process.env.VT_API_KEY;

const redFlagDomains = [
  "xyz", "tk", "ml", "phishing.com", "scamlink.net",
  "secure-login.com", "bank-secure-update.com", "login-alert.net",
  "verify-payment.net", "signin-now.com", "customer-support-online.com", "secure-access.cloud"
];

const suspiciousEmails = [
  "support@paypal.verify.com", "admin@updatemybank.ru",
  "secure@m1crosoft.com", "verify@paypa1.com", "help@goog1e.com",
  "alerts@chase-online-update.com", "billing@netfIix.com"
];

const phishingKeywords = [
  "urgent", "verify account", "suspended", "click here", "act now", "limited time",
  "congratulations", "you've won", "claim now", "update payment", "confirm identity",
  "security alert", "unusual activity", "account locked", "expires today", "final notice",
  "immediate action", "verify now", "account closure", "refund pending", "tax refund",
  "free gift", "prize", "login to continue", "unauthorized access", "confirm your password",
  "new device login", "reset your account", "your action is required", "we noticed suspicious login"
];

const suspiciousPatterns = [
  /\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b/, // Credit card pattern
  /\b\d{3}[-\s]\d{2}[-\s]\d{4}\b/, // SSN pattern
  /password.*[:=]\s*\w+/i, // Password requests
  /pin.*[:=]\s*\d+/i, // PIN requests
  /routing.*number/i, // Banking info
  /account.*number/i, // Account numbers
  /(?:\d{6})/, // OTP codes
  /\b(?:\d{2,4})[- ]?(?:\d{2,4})[- ]?(?:\d{2,4})[- ]?(?:\d{2,4})\b/, // Flexible card numbers
  /cvv.*[:=]?\s*\d{3,4}/i, // CVV capture
  /dob.*[:=]?\s*\d{2}[-/]\d{2}[-/]\d{4}/i, // Date of birth
  /ssn.*[:=]?\s*\d{3}[- ]?\d{2}[- ]?\d{4}/i, // Another SSN pattern
  /login.*here/i, // Login link
  /enter.*account.*info/i,
  /provide.*credentials/i,
];

function isEmail(input) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
}

function customCheck(input) {
  input = input.toLowerCase();
  let score = 100;
  let message = "Looks safe.";
  let flags = [];
  let customMessages = [];

  // Check for red flag domains
  for (const domain of redFlagDomains) {
    if (input.includes(domain)) {
      score -= 30;
      flags.push("Red flag domain detected");
      customMessages.push(`Contains suspicious domain: ${domain}`);
    }
  }

  // Check for suspicious emails
  for (const email of suspiciousEmails) {
    if (input.includes(email)) {
      score -= 40;
      flags.push("Known phishing email detected");
      customMessages.push(`Contains known phishing email: ${email}`);
    }
  }

  // Check for phishing keywords
  for (const keyword of phishingKeywords) {
    if (input.includes(keyword)) {
      score -= 5;
      flags.push("Phishing keyword detected");
      customMessages.push(`Contains suspicious keyword: "${keyword}"`);
    }
  }

  // Check for suspicious patterns
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(input)) {
      score -= 25;
      flags.push("Suspicious pattern detected");
      customMessages.push("Contains patterns commonly used in phishing attempts");
    }
  }

  // Determine final message
  if (score <= 20) {
    message = "HIGHLY SUSPICIOUS - Likely phishing attempt!";
  } else if (score <= 40) {
    message = "SUSPICIOUS - Exercise extreme caution!";
  } else if (score <= 60) {
    message = "CAUTION - Several red flags detected.";
  } else if (score <= 80) {
    message = "Be careful - Some concerns detected.";
  }

  return {
    score: Math.max(0, score),
    message,
    flags,
    customMessages
  };
}

// =============================================================================
// ROUTES - AUTHENTICATION
// =============================================================================

// Send OTP for registration
app.post('/api/auth/sendotp', [
  body('email').isEmail().withMessage('Please enter a valid email').normalizeEmail()
], handleValidationErrors, async (req, res) => {
  try {
    console.log('📝 Sending OTP for registration...');
    const { email } = req.body;
    
    if (await User.findOne({ email })) {
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

    const otpObj = await OTP.create({ email, otp });

    // Send OTP email
    const emailSent = await emailsender(
      email, 
      'FinEduGuard - Email Verification OTP',
      `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
          <h1 style="color: white; margin: 0;">Unified Security Platform</h1>
          <p style="color: white; margin: 5px 0;">Secure Financial Education & Cyber Protection</p>
        </div>
        
        <div style="padding: 30px; background: #f8f9fa;">
          <h2 style="color: #151717; margin-bottom: 20px;">Email Verification</h2>
          <p style="color: #666; line-height: 1.6;">
            Thank you for signing up! To complete your registration, please use the verification code below:
          </p>
          
          <div style="background: #151717; color: white; padding: 20px; text-align: center; margin: 30px 0; border-radius: 10px;">
            <h1 style="font-size: 32px; margin: 0; letter-spacing: 5px;">${otp}</h1>
          </div>
          
          <p style="color: #666; line-height: 1.6;">
            This code will expire in 10 minutes. If you didn't request this verification, please ignore this email.
          </p>
        </div>
      </div>
      `
    );

    if (!emailSent) {
      return res.status(500).json({
        success: false,
        message: 'Failed to send OTP email'
      });
    }

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
});

// Sign up user
app.post('/api/auth/signup', [
  body('firstName').trim().isLength({ min: 2, max: 50 }).withMessage('First name must be between 2 and 50 characters'),
  body('lastName').trim().isLength({ min: 2, max: 50 }).withMessage('Last name must be between 2 and 50 characters'),
  body('email').isEmail().withMessage('Please enter a valid email').normalizeEmail(),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  body('otp').isLength({ min: 4, max: 4 }).withMessage('OTP must be 4 characters long')
], handleValidationErrors, async (req, res) => {
  try {
    const { firstName, lastName, email, password, otp } = req.body;

    if (!(firstName && lastName && email && password && otp)) {
      return res.status(403).json({
        success: false,
        message: "Some fields are missing"
      });
    }

    // Find the most recent OTP for the email
    const recentOtp = await OTP.find({ email }).sort({ createdAt: -1 }).limit(1);

    if (recentOtp.length === 0 || otp !== recentOtp[0].otp) {
      return res.status(400).json({
        success: false,
        message: 'OTP is not valid. Please try again'
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exist. Please sign in to continue'
      });
    }

    const profile = await Profile.create({});

    const user = await User.create({
      firstName,
      lastName,
      email,
      password,
      profile: profile._id,
      avatar: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName}%20${lastName}`,
    });

    // Clear the used OTP
    await OTP.deleteOne({ _id: recentOtp[0]._id });

    sendTokenResponse(res, user, 201);

  } catch (error) {
    console.error('❌ Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to sign up. Please try again',
      error: error.message,
    });
  }
});

// Login user
app.post('/api/auth/login', [
  body('email').isEmail().withMessage('Please enter a valid email').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required')
], handleValidationErrors, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(403).json({
        success: false,
        message: "Some fields are missing"
      });
    }

    const user = await User.findOne({ email }).select('+password');

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials"
      });
    }

    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials"
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    sendTokenResponse(res, user, 200);

  } catch (err) {
    console.error('❌ Login error:', err);
    return res.status(500).json({
      success: false,
      message: "Login failed. Please try again"
    });
  }
});

// Logout user
app.post('/api/auth/logout', protect, async (req, res) => {
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
});

// Get current user
app.get('/api/auth/me', protect, async (req, res) => {
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
});

// =============================================================================
// ROUTES - DOCUMENT HASH MANAGEMENT
// =============================================================================

// Save document
app.post('/api/documents', async (req, res) => {
  try {
    const doc = new Document(req.body);
    await doc.save();
    res.status(201).json(doc);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Get all documents (optionally by wallet)
app.get('/api/documents', async (req, res) => {
  try {
    const { walletAddress } = req.query;
    let docs;
    if (walletAddress) {
      docs = await Document.find({ walletAddress: { $regex: new RegExp('^' + walletAddress + '$', 'i') } });
    } else {
      docs = await Document.find();
    }
    res.json(docs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get document by hash
app.get('/api/documents/hash/:hash', async (req, res) => {
  try {
    const hash = req.params.hash.trim().toLowerCase();
    const doc = await Document.findOne({ hash: { $regex: new RegExp('^' + hash + '$', 'i') } });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete document by id
app.delete('/api/documents/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await Document.findByIdAndDelete(id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =============================================================================
// ROUTES - PHISHING DETECTION
// =============================================================================

// Check if input is phishing
app.post('/api/phishing/check', async (req, res) => {
  try {
    const { input } = req.body;
    
    if (!input) {
      return res.status(400).json({ 
        error: 'Input is required',
        score: 0,
        message: 'No input provided'
      });
    }

    console.log(`Checking input: ${input}`);
    
    let result;
    
    if (isEmail(input)) {
      console.log('Input detected as email');
      result = customCheck(input);
    } else {
      console.log('Input detected as URL/text');
      result = customCheck(input);
      
      // For URLs, also try VirusTotal if API key is available
      if (VT_API_KEY && (input.startsWith('http://') || input.startsWith('https://'))) {
        try {
          console.log('Checking with VirusTotal...');
          const vtResponse = await fetch(`https://www.virustotal.com/vtapi/v2/url/report?apikey=${VT_API_KEY}&resource=${encodeURIComponent(input)}`);
          const vtData = await vtResponse.json();
          
          if (vtData.response_code === 1) {
            const positives = vtData.positives || 0;
            const total = vtData.total || 1;
            const vtScore = Math.max(0, 100 - (positives / total) * 100);
            
            if (positives > 0) {
              result.score = Math.min(result.score, vtScore);
              result.flags.push(`VirusTotal detection: ${positives}/${total} engines flagged as malicious`);
              result.customMessages.push(`VirusTotal found ${positives} security vendors flagging this URL`);
            }
          }
        } catch (vtError) {
          console.log('VirusTotal check failed:', vtError.message);
          result.customMessages.push('External security check unavailable');
        }
      }
    }

    console.log(`Final score: ${result.score}`);
    
    res.json({
      input,
      isPhishing: result.score < 50,
      score: result.score,
      message: result.message,
      flags: result.flags,
      customMessages: result.customMessages,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Phishing check error:', error);
    res.status(500).json({
      error: 'Failed to check input',
      message: error.message
    });
  }
});

// =============================================================================
// ROUTES - CYBER CELLS (NEARBY POLICE STATIONS)
// =============================================================================

const API_KEY = process.env.MAPS_API_KEY || "AlzaSy6c_lnJIj7yBHJNgP8HlJ-l_oUdKTIJ7mw";

app.get("/api/nearby-cybercells", async (req, res) => {
  const { lat, lng, radius = 100000 } = req.query;

  try {
    const response = await axios.get(
      `https://maps.gomaps.pro/maps/api/place/nearbysearch/json`,
      {
        params: {
          location: `${lat},${lng}`,
          radius,
          keyword: "cyber crime police station",
          key: API_KEY,
          type: "police",
        },
      }
    );

    // Use pagination to get more results
    let results = response.data.results;

    if (response.data.next_page_token) {
      const nextPage = await axios.get(
        `https://maps.gomaps.pro/maps/api/place/nearbysearch/json`,
        {
          params: {
            pagetoken: response.data.next_page_token,
            key: API_KEY,
          },
        }
      );
      results = [...results, ...nextPage.data.results];
    }

    const places = await Promise.all(
      results.map(async (place) => {
        const details = await axios.get(
          `https://maps.gomaps.pro/maps/api/place/details/json`,
          {
            params: {
              place_id: place.place_id,
              key: API_KEY,
              fields:
                "name,formatted_address,formatted_phone_number,international_phone_number,website",
            },
          }
        );

        return {
          id: place.place_id,
          name: place.name,
          lat: place.geometry.location.lat,
          lng: place.geometry.location.lng,
          address: details.data.result.formatted_address,
          phone:
            details.data.result.formatted_phone_number ||
            details.data.result.international_phone_number ||
            "N/A",
          email: details.data.result.website || "N/A",
        };
      })
    );

    res.json(places);
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({ error: "Failed to fetch cyber cells" });
  }
});

// =============================================================================
// GENERAL ROUTES
// =============================================================================

// Health check route
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Unified Security Platform API is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
    services: {
      auth: true,
      documents: true,
      phishing: true,
      cyberCells: true
    }
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      message: 'Validation Error',
      errors: Object.values(err.errors).map(e => e.message)
    });
  }
  
  if (err.name === 'CastError') {
    return res.status(400).json({
      success: false,
      message: 'Invalid ID format'
    });
  }
  
  res.status(500).json({
    success: false,
    message: 'Internal server error'
  });
});

// =============================================================================
// DATABASE CONNECTION AND SERVER START
// =============================================================================

// Connect to MongoDB
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log(`MongoDB Connected: ${conn.connection.host}`);
    return true;
  } catch (error) {
    console.error('MongoDB connection error:', error);
    return false;
  }
};

// Start server
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  try {
    console.log('🚀 Starting Unified Security Platform Server...');
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔧 Port: ${PORT}`);
    
    // Connect to MongoDB
    const dbConnected = await connectDB();
    if (!dbConnected) {
      console.error('❌ Failed to connect to MongoDB');
      process.exit(1);
    }
    
    // Test email service if configured
    if (process.env.EMAIL_HOST && process.env.EMAIL_USER) {
      await testEmailConnection();
    } else {
      console.log('⚠️ Email service not configured - auth features will be limited');
    }
    
    // Start the server
    app.listen(PORT, '0.0.0.0', () => {
      console.log('✅ Server started successfully!');
      console.log(`🌐 Server URL: http://localhost:${PORT}`);
      console.log(`📚 API URL: http://localhost:${PORT}/api`);
      console.log(`🔍 Health Check: http://localhost:${PORT}/api/health`);
      console.log('🎉 Unified Security Platform is ready!');
      console.log('🔧 Available Services:');
      console.log('   📧 Authentication & User Management');
      console.log('   📄 Document Hash Management');
      console.log('   🎣 Phishing Detection');
      console.log('   🚨 Nearby Cyber Cells API');
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

// Handle unhandled promise rejections
process.on('unhandledRejection', (err, promise) => {
  console.log(`❌ Unhandled Rejection: ${err.message}`);
  process.exit(1);
});