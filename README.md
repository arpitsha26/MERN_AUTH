# MERN Backend API

This is a backend API built using Node.js, Express, MongoDB, and JWT for authentication. It supports user registration, login, logout, email verification via OTP, password reset via OTP, and fetching user data.

## Features

- Register and login with hashed passwords.
- JWT-based authentication with secure HTTP-only cookies.
- Email verification using OTP
- Password reset functionality
- Middleware-protected routes for user authentication
- Nodemailer integration for sending OTPs

---

## Technologies Used

- Node.js
- Express.js
- MongoDB with Mongoose
- JWT (jsonwebtoken)
- bcrypt.js
- dotenv
- cookie-parser
- cors
- nodemailer

---

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/arpitsha26/MERN_AUTH.git
2. Install dependencies:
   ```bash
   npm install
3. Create a .env file in the root with the following:
   ```bash
    PORT=4000
    MONGODB_URI=your_mongodb_connection_string
    JWT_SECRET=your_jwt_secret_key
    SENDER_EMAIL=your_email@example.com
    EMAIL_PASSWORD=your_email_password
    NODE_ENV=development
4. Start the server:
   ```bash
   npm run start

User Schema (MongoDB - Mongoose)
```bash
  {
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  verifyOtp: { type: String, default: '' },
  verifyOtpExpireAt: { type: Number, default: 0 },
  isAccountVerified: { type: Boolean, default: false },
  resetOtp: { type: String, default: '' },
  resetOtpExpireAt: { type: Number, default: 0 }
  }
```
## API Endpoints

### Base URL: `/api`

### Auth Routes (`/api/auth`)

| Method | Endpoint             | Description                    | Auth Required |
|--------|----------------------|--------------------------------|----------------|
| POST   | `/register`          | Register new user              | ❌             |
| POST   | `/login`             | Login existing user            | ❌             |
| POST   | `/logout`            | Logout user                    | ❌             |
| POST   | `/send-verify-otp`   | Send OTP to verify email       | ✅             |
| POST   | `/verify-account`    | Verify user email with OTP     | ✅             |
| POST   | `/is-auth`           | Check if user is authenticated | ✅             |
| POST   | `/send-reset-otp`    | Send password reset OTP        | ❌             |
| POST   | `/reset-password`    | Reset password using OTP       | ❌             |

---

### User Routes (`/api/user`)

| Method | Endpoint    | Description      | Auth Required |
|--------|-------------|------------------|----------------|
| GET    | `/data`     | Fetch user data  | ✅             |


Sample Postman Requests
1. Register
POST /api/auth/register
  ```bash
   {
  "name": "John Doe",
  "email": "john@example.com",
  "password": "yourpassword"
 }
```

2. Login
POST /api/auth/login
  ```bash
{
  "email": "john@example.com",
  "password": "yourpassword"
}
```

3. Send Email Verification OTP
POST /api/auth/send-verify-otp
(Requires Auth Cookie)
```bash
{}
```

4. Verify Account
POST /api/auth/verify-account
```bash
{
  "userId": "64adfd8e1a37bb0f08f10b20",
  "otp": "123456"
}
```
5. Send Password Reset OTP
POST /api/auth/send-reset-otp
``` bash
{
  "email": "john@example.com"
}
```
6. Reset Password
POST /api/auth/reset-password
``` bash
{
  "email": "john@example.com",
  "otp": "123456",
  "newPassword": "newSecurePassword"
}
```




Deployed url:- http://aplats-env.eba-uyjg4ztm.ap-south-1.elasticbeanstalk.com/


   

   


