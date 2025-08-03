# FinEduGuard Backend API

A secure Node.js/Express backend API for the FinEduGuard financial education app with user authentication, email verification, and password management.

## Features

- ✅ User Registration with Email Verification
- ✅ Secure Login with JWT Authentication
- ✅ OTP-based Email Verification
- ✅ Password Reset with Email OTP
- ✅ Input Validation and Sanitization
- ✅ Rate Limiting and Security Headers
- ✅ MongoDB Database Integration
- ✅ Professional Email Templates

## Tech Stack

- **Node.js** - Runtime environment
- **Express.js** - Web framework
- **MongoDB** - Database
- **Mongoose** - ODM for MongoDB
- **JWT** - Authentication tokens
- **bcryptjs** - Password hashing
- **nodemailer** - Email service
- **express-validator** - Input validation
- **helmet** - Security headers
- **cors** - Cross-origin resource sharing

## Installation

1. **Install Dependencies**
   ```bash
   cd backend
   npm install
   ```

2. **Setup Environment Variables**
   - Copy `config.env` and update the values:
   ```bash
   # Update these values in config.env
   MONGODB_URI=mongodb://localhost:27017/fineduguard
   JWT_SECRET=your-super-secret-jwt-key
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASS=your-app-password
   ```

3. **Setup MongoDB**
   - Install MongoDB locally or use MongoDB Atlas
   - Create a database named `fineduguard`

4. **Setup Email Service**
   - For Gmail: Enable 2-factor authentication and generate an app password
   - Update `EMAIL_USER` and `EMAIL_PASS` in config.env

## Running the Server

### Development Mode
```bash
npm run dev
```

### Production Mode
```bash
npm start
```

The server will start on `http://localhost:5000`

## API Endpoints

### Authentication Routes

#### 1. Register User
```
POST /api/auth/register
```
**Body:**
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john@example.com",
  "password": "password123"
}
```

#### 2. Login User
```
POST /api/auth/login
```
**Body:**
```json
{
  "email": "john@example.com",
  "password": "password123"
}
```

#### 3. Verify Email OTP
```
POST /api/auth/verify-email
```
**Body:**
```json
{
  "email": "john@example.com",
  "otp": "1234"
}
```

#### 4. Resend Verification Email
```
POST /api/auth/resend-verification
```
**Body:**
```json
{
  "email": "john@example.com"
}
```

#### 5. Forgot Password
```
POST /api/auth/forgot-password
```
**Body:**
```json
{
  "email": "john@example.com"
}
```

#### 6. Reset Password
```
POST /api/auth/reset-password
```
**Body:**
```json
{
  "email": "john@example.com",
  "otp": "1234",
  "newPassword": "newpassword123"
}
```

#### 7. Get Current User
```
GET /api/auth/me
```
**Headers:**
```
Authorization: Bearer <token>
```

#### 8. Logout User
```
POST /api/auth/logout
```
**Headers:**
```
Authorization: Bearer <token>
```

## Response Format

### Success Response
```json
{
  "success": true,
  "message": "Operation successful",
  "data": {
    // Response data
  }
}
```

### Error Response
```json
{
  "success": false,
  "message": "Error description",
  "errors": [
    // Validation errors (if any)
  ]
}
```

## Security Features

- **Password Hashing**: bcryptjs with salt rounds
- **JWT Authentication**: Secure token-based auth
- **Rate Limiting**: Prevents abuse
- **Input Validation**: Sanitizes all inputs
- **CORS Protection**: Configurable origins
- **Security Headers**: Helmet middleware
- **Email Verification**: OTP-based verification

## Database Schema

### User Model
```javascript
{
  firstName: String (required),
  lastName: String (required),
  email: String (required, unique),
  password: String (required, hashed),
  isEmailVerified: Boolean (default: false),
  emailVerificationOTP: {
    code: String,
    expiresAt: Date
  },
  passwordResetOTP: {
    code: String,
    expiresAt: Date
  },
  role: String (enum: ['user', 'admin']),
  isActive: Boolean (default: true),
  lastLogin: Date,
  loginHistory: Array,
  createdAt: Date,
  updatedAt: Date
}
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 5000 |
| `NODE_ENV` | Environment | development |
| `MONGODB_URI` | MongoDB connection string | mongodb://localhost:27017/fineduguard |
| `JWT_SECRET` | JWT signing secret | - |
| `JWT_EXPIRE` | JWT expiration time | 7d |
| `EMAIL_HOST` | SMTP host | smtp.gmail.com |
| `EMAIL_PORT` | SMTP port | 587 |
| `EMAIL_USER` | Email username | - |
| `EMAIL_PASS` | Email password | - |

## Testing the API

### Using curl

1. **Register a user:**
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "John",
    "lastName": "Doe",
    "email": "john@example.com",
    "password": "password123"
  }'
```

2. **Login:**
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "password123"
  }'
```

3. **Verify email (use OTP from email):**
```bash
curl -X POST http://localhost:5000/api/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "otp": "1234"
  }'
```

## Frontend Integration

To connect your React Native frontend:

1. **Update API Base URL** in your frontend
2. **Handle API Responses** properly
3. **Store JWT Token** securely
4. **Add Authorization Headers** to protected requests

Example frontend API call:
```javascript
const loginUser = async (email, password) => {
  try {
    const response = await fetch('http://localhost:5000/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });
    
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Login error:', error);
    throw error;
  }
};
```

## Production Deployment

1. **Update Environment Variables** for production
2. **Use MongoDB Atlas** or production MongoDB instance
3. **Setup Email Service** (SendGrid, AWS SES, etc.)
4. **Add SSL Certificate** for HTTPS
5. **Setup PM2** or similar process manager
6. **Configure Nginx** as reverse proxy

## License

MIT License - see LICENSE file for details 