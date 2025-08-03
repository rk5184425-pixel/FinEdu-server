require('dotenv').config({ path: './config.env' });
const { sendEmailVerificationOTP } = require('./utils/emailService');

const testEmail = async () => {
  console.log('🧪 Testing email functionality...');
  console.log('📧 Environment variables:');
  console.log(`   EMAIL_HOST: ${process.env.EMAIL_HOST}`);
  console.log(`   EMAIL_PORT: ${process.env.EMAIL_PORT}`);
  console.log(`   EMAIL_USER: ${process.env.EMAIL_USER}`);
  console.log(`   FROM_NAME: ${process.env.FROM_NAME}`);
  console.log(`   FROM_EMAIL: ${process.env.FROM_EMAIL}`);
  console.log(`   SITE_OWNER_EMAIL: ${process.env.SITE_OWNER_EMAIL}`);
  
  try {
    const result = await sendEmailVerificationOTP(
      process.env.SITE_OWNER_EMAIL,
      '1234',
      'Test User'
    );
    
    if (result) {
      console.log('✅ Email test successful!');
      console.log('📧 Check your email inbox for the test email.');
    } else {
      console.log('❌ Email test failed!');
    }
  } catch (error) {
    console.error('❌ Email test error:', error);
  }
};

testEmail(); 