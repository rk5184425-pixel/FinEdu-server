const nodemailer = require('nodemailer');

// Create transporter
const createTransporter = () => {
  console.log('🔧 Creating email transporter...');
  console.log(`📧 Host: ${process.env.EMAIL_HOST}`);
  console.log(`📧 Port: ${process.env.EMAIL_PORT}`);
  console.log(`📧 User: ${process.env.EMAIL_USER}`);
  console.log(`📧 From Name: ${process.env.FROM_NAME}`);
  console.log(`📧 From Email: ${process.env.FROM_EMAIL}`);
  
  return nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false, // true for 465, false for other ports
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
};

// Test email configuration
const testEmailConnection = async () => {
  try {
    console.log('🔧 Testing email configuration...');
    console.log(`📧 Email Host: ${process.env.EMAIL_HOST}`);
    console.log(`📧 Email User: ${process.env.EMAIL_USER}`);
    console.log(`📧 From Name: ${process.env.FROM_NAME}`);
    
    const transporter = createTransporter();
    
    // Verify connection configuration
    console.log('🔍 Verifying SMTP connection...');
    await transporter.verify();
    console.log('✅ Email configuration is valid');
    
    // Send test email
    const testMailOptions = {
      from: `"${process.env.FROM_NAME}" <${process.env.FROM_EMAIL}>`,
      to: process.env.SITE_OWNER_EMAIL,
      subject: "FinEduGuard - Email Service Test",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">FinEduGuard</h1>
            <p style="color: white; margin: 5px 0;">Secure Financial Education</p>
          </div>
          
          <div style="padding: 30px; background: #f8f9fa;">
            <h2 style="color: #151717; margin-bottom: 20px;">Email Service Test</h2>
            <p style="color: #666; line-height: 1.6;">
              Hello ${process.env.FROM_NAME},
            </p>
            <p style="color: #666; line-height: 1.6;">
              This is a test email to verify that the FinEduGuard email service is working correctly.
            </p>
            
            <div style="background: #151717; color: white; padding: 20px; text-align: center; margin: 30px 0; border-radius: 10px;">
              <h3 style="margin: 0;">✅ Email Service Active</h3>
              <p style="margin: 10px 0 0 0; font-size: 14px;">
                Server started successfully at ${new Date().toLocaleString()}
              </p>
            </div>
            
            <p style="color: #666; line-height: 1.6;">
              The email service is now ready to send:
            </p>
            <ul style="color: #666; line-height: 1.6;">
              <li>Email verification OTPs</li>
              <li>Password reset codes</li>
              <li>Account notifications</li>
            </ul>
            
            <p style="color: #666; line-height: 1.6;">
              Best regards,<br>
              FinEduGuard System
            </p>
          </div>
          
          <div style="background: #151717; color: white; padding: 20px; text-align: center;">
            <p style="margin: 0; font-size: 12px;">
              © 2024 FinEduGuard. All rights reserved.
            </p>
          </div>
        </div>
      `
    };

    console.log('📤 Sending test email...');
    const info = await transporter.sendMail(testMailOptions);
    console.log('✅ Test email sent successfully');
    console.log(`📧 Message ID: ${info.messageId}`);
    console.log(`📧 To: ${process.env.SITE_OWNER_EMAIL}`);
    return true;
  } catch (error) {
    console.error('❌ Email configuration test failed:', error.message);
    console.error('🔧 Please check your email settings in config.env');
    console.error('📧 Make sure your Gmail app password is correct');
    console.error('📧 Full error:', error);
    return false;
  }
};

// Send email verification OTP
const sendEmailVerificationOTP = async (email, otp, firstName) => {
  try {
    console.log('📧 Sending email verification OTP...');
    console.log(`📧 To: ${email}`);
    console.log(`📧 OTP: ${otp}`);
    console.log(`📧 Name: ${firstName}`);
    
    const transporter = createTransporter();
    
    const mailOptions = {
      from: `"${process.env.FROM_NAME}" <${process.env.FROM_EMAIL}>`,
      to: email,
      subject: "Verify Your Email - FinEduGuard",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">FinEduGuard</h1>
            <p style="color: white; margin: 5px 0;">Secure Financial Education</p>
          </div>
          
          <div style="padding: 30px; background: #f8f9fa;">
            <h2 style="color: #151717; margin-bottom: 20px;">Email Verification</h2>
            <p style="color: #666; line-height: 1.6;">
              Hi ${firstName},
            </p>
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
    };

    console.log('📤 Sending verification email...');
    const info = await transporter.sendMail(mailOptions);
    console.log('✅ Email verification OTP sent successfully');
    console.log(`📧 Message ID: ${info.messageId}`);
    console.log(`📧 To: ${email}`);
    return true;
  } catch (error) {
    console.error('❌ Email verification OTP sending failed:', error.message);
    console.error('📧 Full error:', error);
    return false;
  }
};

// Send password reset OTP
const sendPasswordResetOTP = async (email, otp, firstName) => {
  try {
    console.log('📧 Sending password reset OTP...');
    console.log(`📧 To: ${email}`);
    console.log(`📧 OTP: ${otp}`);
    console.log(`📧 Name: ${firstName}`);
    
    const transporter = createTransporter();
    
    const mailOptions = {
      from: `"${process.env.FROM_NAME}" <${process.env.FROM_EMAIL}>`,
      to: email,
      subject: "Password Reset - FinEduGuard",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">FinEduGuard</h1>
            <p style="color: white; margin: 5px 0;">Secure Financial Education</p>
          </div>
          
          <div style="padding: 30px; background: #f8f9fa;">
            <h2 style="color: #151717; margin-bottom: 20px;">Password Reset</h2>
            <p style="color: #666; line-height: 1.6;">
              Hi ${firstName},
            </p>
            <p style="color: #666; line-height: 1.6;">
              You requested a password reset for your FinEduGuard account. Use the verification code below to reset your password:
            </p>
            
            <div style="background: #151717; color: white; padding: 20px; text-align: center; margin: 30px 0; border-radius: 10px;">
              <h1 style="font-size: 32px; margin: 0; letter-spacing: 5px;">${otp}</h1>
            </div>
            
            <p style="color: #666; line-height: 1.6;">
              This code will expire in 10 minutes. If you didn't request this reset, please ignore this email and your password will remain unchanged.
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
    };

    console.log('📤 Sending password reset email...');
    const info = await transporter.sendMail(mailOptions);
    console.log('✅ Password reset OTP sent successfully');
    console.log(`📧 Message ID: ${info.messageId}`);
    console.log(`📧 To: ${email}`);
    return true;
  } catch (error) {
    console.error('❌ Password reset OTP sending failed:', error.message);
    console.error('📧 Full error:', error);
    return false;
  }
};

module.exports = {
  testEmailConnection,
  sendEmailVerificationOTP,
  sendPasswordResetOTP
}; 