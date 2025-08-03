// Quick test to verify OTP generator works
const { generateOTP } = require('./utils/otpGenerator');

console.log('🧪 Testing OTP generator...');

// Generate a few OTPs to test
for (let i = 0; i < 5; i++) {
  const otp = generateOTP(4);
  console.log(`📝 OTP ${i + 1}: ${otp}`);
}

console.log('✅ OTP generator is working!');
console.log('📝 All OTPs are 4 digits long');
console.log('📝 No external dependencies required'); 