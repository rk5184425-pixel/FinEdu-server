const nodemailer = require('nodemailer');

const emailsender = async (email, subject, html) => {
  try {
    console.log('📧 Sending email...');
    console.log(`📧 To: ${email}`);
    console.log(`📧 Subject: ${subject}`);
    
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false, // true for 465, false for other ports
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

module.exports = emailsender; 