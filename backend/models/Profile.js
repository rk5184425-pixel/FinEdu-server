const mongoose = require('mongoose');

const profileSchema = new mongoose.Schema({
  // Basic Information
  firstName: {
    type: String,
    trim: true
  },
  lastName: {
    type: String,
    trim: true
  },
  email: {
    type: String,
    trim: true,
    lowercase: true
  },
  phoneNumber: {
    type: String,
    trim: true
  },
  dateOfBirth: {
    type: Date
  },
  gender: {
    type: String,
    enum: ['male', 'female', 'other', 'prefer-not-to-say']
  },
  
  // Address Information
  address: {
    street: String,
    city: String,
    state: String,
    country: String,
    zipCode: String
  },
  
  // Professional Information
  occupation: {
    type: String,
    trim: true
  },
  company: {
    type: String,
    trim: true
  },
  education: {
    degree: String,
    institution: String,
    graduationYear: Number
  },
  
  // Financial Information
  incomeRange: {
    type: String,
    enum: ['under-25k', '25k-50k', '50k-75k', '75k-100k', '100k-150k', 'over-150k']
  },
  investmentExperience: {
    type: String,
    enum: ['beginner', 'intermediate', 'advanced', 'expert']
  },
  
  // Preferences
  interests: [{
    type: String,
    enum: ['stocks', 'bonds', 'crypto', 'real-estate', 'mutual-funds', 'etfs', 'retirement-planning', 'tax-planning', 'insurance']
  }],
  
  // Social Links
  linkedin: String,
  twitter: String,
  website: String,
  
  // Profile Settings
  isPublic: {
    type: Boolean,
    default: false
  },
  allowNotifications: {
    type: Boolean,
    default: true
  },
  
  // Timestamps
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update the updatedAt field before saving
profileSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Profile', profileSchema); 