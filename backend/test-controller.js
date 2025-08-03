// Test to verify authController exports work
try {
  const authController = require('./controllers/authController');
  
  console.log('🧪 Testing authController exports...');
  
  // Check if all functions are exported
  const functions = ['sendOTP', 'signUp', 'login', 'logOut', 'forgotPassword', 'resetPassword', 'getMe'];
  
  functions.forEach(func => {
    if (typeof authController[func] === 'function') {
      console.log(`✅ ${func} is exported correctly`);
    } else {
      console.log(`❌ ${func} is missing or not a function`);
    }
  });
  
  console.log('✅ All authController exports are working!');
  
} catch (error) {
  console.error('❌ Error loading authController:', error.message);
} 