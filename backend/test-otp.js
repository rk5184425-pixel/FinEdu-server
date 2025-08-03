require('dotenv').config({ path: './config.env' });
const { generateOTP } = require('./utils/otpGenerator');
const emailsender = require('./utils/emailsender');

const testOTP = async () => {
  console.log('🧪 Testing OTP generation and email...');
  
  // Test OTP generation
  const otp = generateOTP(4);
  console.log(`📝 Generated OTP: ${otp}`);
  
  // Test email sending
  console.log('📧 Testing email sending...');
  const emailSent = await emailsender(
    process.env.SITE_OWNER_EMAIL,
    'FinEduGuard - Test Email',
    `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
        <h1 style="color: white; margin: 0;">FinEduGuard</h1>
        <p style="color: white; margin: 5px 0;">Secure Financial Education</p>
      </div>
      
      <div style="padding: 30px; background: #f8f9fa;">
        <h2 style="color: #151717; margin-bottom: 20px;">Test Email</h2>
        <p style="color: #666; line-height: 1.6;">
          This is a test email to verify that the email service is working correctly.
        </p>
        
        <div style="background: #151717; color: white; padding: 20px; text-align: center; margin: 30px 0; border-radius: 10px;">
          <h3 style="margin: 0;">✅ Test Successful</h3>
          <p style="margin: 10px 0 0 0; font-size: 14px;">
            OTP: ${otp}
          </p>
        </div>
        
        <p style="color: #666; line-height: 1.6;">
          If you received this email, the email service is working correctly.
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
  
  if (emailSent) {
    console.log('✅ Test successful! Email sent and OTP generated.');
    console.log('📧 Check your email inbox for the test email.');
  } else {
    console.log('❌ Test failed! Email could not be sent.');
  }
};

testOTP(); 