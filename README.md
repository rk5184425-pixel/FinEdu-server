# Unified Security Platform Server

A comprehensive security platform that combines multiple security services into a single, unified server. This platform integrates authentication, document management, phishing detection, and cyber cell location services.

## 🚀 Features

### 1. **Authentication & User Management**
- User registration with OTP verification via email
- JWT-based authentication
- Password reset functionality
- User profile management
- Secure password hashing with bcrypt

### 2. **Document Hash Management**
- Store and retrieve document hashes
- Wallet address integration for blockchain applications
- Document verification by hash lookup
- CRUD operations for document records

### 3. **Phishing Detection**
- Real-time phishing detection for URLs and emails
- Custom scoring algorithm with multiple security checks
- VirusTotal integration for enhanced threat detection
- Pattern matching for suspicious content

### 4. **Cyber Cell Location Service**
- Find nearby cyber crime police stations
- Google Maps integration for location services
- Detailed information including contact details
- Radius-based search functionality

## 🛠 Technology Stack

- **Runtime:** Node.js with ES6+ modules
- **Framework:** Express.js
- **Database:** MongoDB with Mongoose ODM
- **Authentication:** JWT (JSON Web Tokens)
- **Security:** Helmet, Rate Limiting, CORS
- **Email:** Nodemailer with SMTP support
- **External APIs:** VirusTotal, Google Maps Places API

## 📋 Prerequisites

- Node.js (v16 or higher)
- MongoDB (local or MongoDB Atlas)
- SMTP email service (Gmail recommended)
- Google Maps API key (optional, for cyber cell service)
- VirusTotal API key (optional, for enhanced phishing detection)

## 🔧 Installation & Setup

### 1. Clone and Install Dependencies

```bash
# Install dependencies
npm install
```

### 2. Environment Configuration

```bash
# Copy the environment template
cp .env.example .env

# Edit the .env file with your actual configuration
nano .env
```

### 3. Required Environment Variables

Fill in the following required variables in your `.env` file:

```env
# Database
MONGODB_URI=mongodb://localhost:27017/unified-security-platform

# JWT
JWT_SECRET=your-super-secure-jwt-secret-key-here

# Email Service (for OTP)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
FROM_NAME=Unified Security Platform
FROM_EMAIL=your-email@gmail.com
```

### 4. Optional API Keys

For enhanced functionality, add these optional API keys:

```env
# VirusTotal (for enhanced phishing detection)
VT_API_KEY=your-virustotal-api-key

# Google Maps (for cyber cell locations)
MAPS_API_KEY=your-google-maps-api-key
```

### 5. Start the Server

```bash
# Development mode
npm run dev

# Production mode
npm start
```

The server will start on `http://localhost:5000` by default.

## 📚 API Documentation

### Authentication Endpoints

#### POST `/api/auth/sendotp`
Send OTP for registration
```json
{
  "email": "user@example.com"
}
```

#### POST `/api/auth/signup`
Register new user
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "user@example.com",
  "password": "password123",
  "otp": "1234"
}
```

#### POST `/api/auth/login`
User login
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

#### GET `/api/auth/me`
Get current user (requires Bearer token)

#### POST `/api/auth/logout`
Logout user (requires Bearer token)

### Document Management Endpoints

#### POST `/api/documents`
Store document hash
```json
{
  "filename": "document.pdf",
  "hash": "abc123...",
  "walletAddress": "0x123...",
  "timestamp": 1640995200,
  "size": 1024,
  "type": "pdf"
}
```

#### GET `/api/documents`
Get all documents (optional: `?walletAddress=0x123...`)

#### GET `/api/documents/hash/:hash`
Get document by hash

#### DELETE `/api/documents/:id`
Delete document by ID

### Phishing Detection Endpoints

#### POST `/api/phishing/check`
Check URL or email for phishing
```json
{
  "input": "https://suspicious-site.com"
}
```

Response includes:
- `score`: Safety score (0-100)
- `isPhishing`: Boolean flag
- `flags`: Array of detected issues
- `customMessages`: Detailed explanations

### Cyber Cell Location Endpoints

#### GET `/api/nearby-cybercells`
Find nearby cyber crime police stations
```
GET /api/nearby-cybercells?lat=28.6139&lng=77.2090&radius=50000
```

Parameters:
- `lat`: Latitude
- `lng`: Longitude  
- `radius`: Search radius in meters (default: 100000)

### Health Check

#### GET `/api/health`
Server health check - returns service status

## 🔒 Security Features

- **Rate Limiting:** Prevents API abuse with configurable limits
- **Helmet:** Adds security headers
- **CORS:** Configurable cross-origin resource sharing
- **JWT Authentication:** Secure token-based authentication
- **Password Hashing:** bcrypt with salt rounds
- **Input Validation:** Express-validator for request validation
- **Environment Variables:** Sensitive data protection

## 🚀 Deployment

### Environment Setup for Production

1. Set `NODE_ENV=production` in your environment
2. Use a secure MongoDB instance (MongoDB Atlas recommended)
3. Configure proper CORS origins
4. Use strong JWT secrets
5. Set up proper logging and monitoring

### Docker Deployment (Optional)

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 5000
CMD ["npm", "start"]
```

### Environment Variables for Production

```env
NODE_ENV=production
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/db
JWT_SECRET=your-super-secure-production-secret
# ... other production settings
```

## 🔧 Configuration

### Rate Limiting
Adjust rate limiting in `.env`:
```env
RATE_LIMIT_WINDOW_MS=900000  # 15 minutes
RATE_LIMIT_MAX_REQUESTS=100  # 100 requests per window
```

### CORS Configuration
Update CORS origins in `unified-server.js` for production:
```javascript
origin: process.env.NODE_ENV === 'production' 
  ? ['https://yourdomain.com'] 
  : ['http://localhost:3000', 'http://localhost:19006', '*']
```

## 🧪 Testing

### Health Check
```bash
curl http://localhost:5000/api/health
```

### Test Authentication
```bash
# Send OTP
curl -X POST http://localhost:5000/api/auth/sendotp \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'
```

### Test Phishing Detection
```bash
curl -X POST http://localhost:5000/api/phishing/check \
  -H "Content-Type: application/json" \
  -d '{"input":"https://suspicious-site.com"}'
```

## 📝 Migration from Separate Servers

This unified server replaces four separate servers:

1. **Main server.js (Port 4000)** → Cyber cells API now at `/api/nearby-cybercells`
2. **Server directory (Port 5000)** → Document hash routes at `/api/documents/*`
3. **Backend directory (Port 5000)** → Authentication routes at `/api/auth/*`
4. **Server copy directory** → Phishing detection at `/api/phishing/*`

All functionalities have been preserved and integrated into a single, cohesive API.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the API documentation above
- Verify your environment configuration
- Check server logs for detailed error messages

## 🔗 Related Links

- [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
- [VirusTotal API](https://www.virustotal.com/gui/join-us)
- [Google Maps API](https://console.cloud.google.com/apis/credentials)
- [Gmail App Passwords](https://support.google.com/accounts/answer/185833)