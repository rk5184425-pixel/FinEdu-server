const axios = require('axios');

const testOTPFlow = async () => {
  console.log('🧪 Testing OTP-based registration flow...');
  
  const testUser = {
    firstName: 'Test',
    lastName: 'User',
    email: 'test@example.com',
    password: 'password123'
  };
  
  try {
    // Step 1: Send OTP
    console.log('📝 Step 1: Sending OTP...');
    const otpResponse = await axios.post('http://localhost:5000/api/auth/send-otp', {
      email: testUser.email
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    console.log('✅ OTP sent successfully!');
    console.log('📧 OTP Response:', otpResponse.data);
    
    // Step 2: Register with OTP
    console.log('📝 Step 2: Registering with OTP...');
    const otp = otpResponse.data.data; // The OTP is returned in the response
    
    const signupResponse = await axios.post('http://localhost:5000/api/auth/signup', {
      ...testUser,
      otp: otp
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    console.log('✅ Registration successful!');
    console.log('📧 Signup Response:', signupResponse.data);
    console.log('📧 Check your email for welcome message');
    
  } catch (error) {
    console.error('❌ Test failed!');
    if (error.response) {
      console.error('📧 Status:', error.response.status);
      console.error('📧 Data:', error.response.data);
    } else {
      console.error('📧 Error:', error.message);
    }
  }
};

const testLogin = async () => {
  console.log('🧪 Testing login...');
  
  try {
    const loginResponse = await axios.post('http://localhost:5000/api/auth/login', {
      email: 'test@example.com',
      password: 'password123'
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    console.log('✅ Login successful!');
    console.log('📧 Login Response:', loginResponse.data);
    
  } catch (error) {
    console.error('❌ Login failed!');
    if (error.response) {
      console.error('📧 Status:', error.response.status);
      console.error('📧 Data:', error.response.data);
    } else {
      console.error('📧 Error:', error.message);
    }
  }
};

// Check if server is running
const checkServer = async () => {
  try {
    console.log('🔍 Checking if server is running...');
    const response = await axios.get('http://localhost:5000/api/health');
    console.log('✅ Server is running!');
    console.log('📧 Health check response:', response.data);
    return true;
  } catch (error) {
    console.error('❌ Server is not running!');
    console.error('📧 Make sure to start the server with: npm run dev');
    return false;
  }
};

const runTests = async () => {
  const serverRunning = await checkServer();
  if (serverRunning) {
    await testOTPFlow();
    console.log('\n---');
    await testLogin();
  }
};

runTests(); 