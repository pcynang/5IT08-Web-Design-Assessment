# User Profile Portal

## Features

- User registration and authentication
- Secure login with session management
- Personal information search and retrieval
- Dynamic theme switching
- Customizable navigation menu
- Password reset functionality (outputs to console, due to lack of email account attached)

## Tech Stack

- Backend: Node.js with Express
- Database: SQLite
- Frontend: Bootstrap 5, Vanilla JavaScript
- Security: bcrypt, express-session, helmet

## Setup

1. Install dependencies:
   npm install

2. Start the server:
   node index.js

3. Access the application:
   - Open http://localhost:3000 in your browser
   - Register a new account
   - Login with your credentials


- Database and sample data are automatically created on first run
- Test accounts are created with sample personal data (IDs: 1001, 1002)

## Security Features

- Password hashing with bcrypt
- Session-based authentication
- Rate limiting
- Input validation
- Error handling

## File Structure

```
├── index.js           # Main server file
├── package.json       # Dependencies
├── personal_data.json # Sample data
├── public/           
│   ├── css/          # Stylesheets
│   └── js/           # Client-side scripts
└── views/            # HTML templates
```
