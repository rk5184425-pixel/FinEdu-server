const accountCreationTemplate = (fullName) => {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center;">
        <h1 style="color: white; margin: 0;">FinEduGuard</h1>
        <p style="color: white; margin: 5px 0;">Secure Financial Education</p>
      </div>
      
      <div style="padding: 30px; background: #f8f9fa;">
        <h2 style="color: #151717; margin-bottom: 20px;">Welcome to FinEduGuard!</h2>
        <p style="color: #666; line-height: 1.6;">
          Hi ${fullName},
        </p>
        <p style="color: #666; line-height: 1.6;">
          Welcome to FinEduGuard! Your account has been created successfully. We're excited to have you join our community of financial education enthusiasts.
        </p>
        
        <div style="background: #151717; color: white; padding: 20px; text-align: center; margin: 30px 0; border-radius: 10px;">
          <h3 style="margin: 0;">🎉 Account Created Successfully</h3>
          <p style="margin: 10px 0 0 0; font-size: 14px;">
            You can now access all our features and start your financial education journey.
          </p>
        </div>
        
        <p style="color: #666; line-height: 1.6;">
          With FinEduGuard, you can:
        </p>
        <ul style="color: #666; line-height: 1.6;">
          <li>Access comprehensive financial education resources</li>
          <li>Learn about investment strategies</li>
          <li>Track your financial progress</li>
          <li>Connect with other learners</li>
          <li>Get personalized financial advice</li>
        </ul>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${process.env.FRONTEND_SITE || 'http://localhost:3000'}" 
             style="background: #151717; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Get Started
          </a>
        </div>
        
        <p style="color: #666; line-height: 1.6;">
          If you have any questions or need assistance, feel free to reach out to our support team.
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
  `;
};

module.exports = accountCreationTemplate; 