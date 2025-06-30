const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs').promises;
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const xml2js = require('xml2js');
const helmet = require('helmet');
const crypto = require('crypto');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Security headers middleware
app.use(helmet({
    contentSecurityPolicy: false, // Disabled for development
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'same-origin' },
    frameguard: { action: 'deny' },
    noSniff: true,
    xssFilter: true
}));

// Additional security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    next();
});

// Security middleware
app.use((req, res, next) => {
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;");
    
    // Prevent caching of sensitive pages
    if (req.path.startsWith('/dashboard') || req.path.startsWith('/profile')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
    }
    
    next();
});

// Static files
app.use(express.static(path.join(__dirname, 'public'), {
    setHeaders: (res, path) => {
        // Don't cache HTML files
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }
    }
}));

// Serve forgot-password page
app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'forgot-password.html'));
});

// Serve reset-password page
app.get('/reset-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'reset-password.html'));
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
const sessionConfig = {
    secret: 'your-secret-key', 
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', 
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000, 
        path: '/'
    },
    rolling: true, 
    unset: 'destroy' 
};

// Trust first proxy if behind a reverse proxy (e.g., Nginx)
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1);
    sessionConfig.cookie.secure = true;
}

// Use session middleware
app.use(session(sessionConfig));

// Rate limiting middleware
const rateLimit = require('express-rate-limit');
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: 'Too many requests from this IP, please try again after 15 minutes'
});

// Apply rate limiting to API routes
app.use('/api/', apiLimiter);

// Database setup
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error('Error connecting to SQLite database:', err);
    } else {
        console.log('Connected to SQLite database');
        // Create users table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            firstName TEXT NOT NULL,
            lastName TEXT NOT NULL,
            theme TEXT,
            menuPreferences TEXT
        )`);
    }
});

// Check if personal_data.json exists, if not create it
async function initializeDataFile() {
    try {
        await fs.access('./personal_data.json');
        console.log('personal_data.json exists');
    } catch (error) {
        console.log('Creating personal_data.json with sample data');
        const sampleData = [
            {
                "idNumber": "1001",
                "personalInfo": {
                    "fullName": "Alice Johnson",
                    "dateOfBirth": "1990-05-15",
                    "address": "123 Maple Street, Anytown",
                    "phone": "555-0101",
                    "emergencyContact": "Bob Johnson (Father)"
                }
            },
            {
                "idNumber": "1002",
                "personalInfo": {
                    "fullName": "Charlie Davis",
                    "dateOfBirth": "1988-11-22",
                    "address": "456 Oak Avenue, Someplace",
                    "phone": "555-0102",
                    "emergencyContact": "Diana Davis (Spouse)"
                }
            }
        ];
        await fs.writeFile('./personal_data.json', JSON.stringify(sampleData, null, 2));
    }
}

initializeDataFile().catch(console.error);

// Configure email transporter (for development only)
const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
        user: 'your-email@example.com',
        pass: 'your-password'
    }
});

// In-memory store for password reset tokens (in production, use a database)
const passwordResetTokens = new Map();

// Generate a secure token
function generateToken() {
    return new Promise((resolve, reject) => {
        crypto.randomBytes(32, (err, buffer) => {
            if (err) reject(err);
            resolve(buffer.toString('hex'));
        });
    });
}

// Send password reset email
async function sendPasswordResetEmail(email, token) {
    // In production, you would send an actual email
    const resetUrl = `http://localhost:3000/reset-password?token=${token}`;
    
    console.log('Sending password reset email to:', email);
    console.log('Reset URL:', resetUrl);
    
    try {
        // In development, log the reset link to console
        const testAccount = await nodemailer.createTestAccount();
        
        const info = await transporter.sendMail({
            from: 'noreply@userportal.com',
            to: email,
            subject: 'Password Reset Request',
            html: `
                <p>You requested a password reset for your account.</p>
                <p>Click this link to reset your password: <a href="${resetUrl}">${resetUrl}</a></p>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request this, please ignore this email.</p>
            `,
            text: `
                You requested a password reset for your account.\n\n` +
                `Please click the following link to reset your password:\n${resetUrl}\n\n` +
                `This link will expire in 1 hour.\n\n` +
                `If you didn't request this, please ignore this email.`
        });
        
        console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
        return true;
    } catch (error) {
        console.error('Error sending email:', error);
        return false;
    }
}

// Authentication middleware with role-based access control
const requireAuth = (roles = []) => {
    return (req, res, next) => {
        if (!req.session || !req.session.user) {
            return res.status(401).json({ 
                success: false,
                error: 'Authentication required',
                code: 'UNAUTHORIZED'
            });
        }
        
        // If roles are specified, check if user has required role
        if (Array.isArray(roles) && roles.length > 0) {
            if (!roles.includes(req.session.user.role)) {
                return res.status(403).json({
                    success: false,
                    error: 'Insufficient permissions',
                    code: 'FORBIDDEN'
                });
            }
        }
        
        next();
    };
};

// Error handling middleware
const errorHandler = (err, req, res, next) => {
    console.error('Error:', err.stack);
    
    // Default error status and message
    const statusCode = err.statusCode || 500;
    const errorResponse = {
        success: false,
        error: err.message || 'Internal Server Error',
        code: err.code || 'INTERNAL_SERVER_ERROR'
    };
    
    // Include validation errors if present
    if (err.errors) {
        errorResponse.errors = err.errors;
    }
    
    // Don't leak stack traces in production
    if (process.env.NODE_ENV === 'development') {
        errorResponse.stack = err.stack;
    }
    
    res.status(statusCode).json(errorResponse);
};

// 404 handler
const notFoundHandler = (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Not Found',
        code: 'NOT_FOUND'
    });
};

// Personal Info API endpoint
app.get('/api/personal-info/:id', requireAuth(), async (req, res) => {
    const { id } = req.params;
    
    try {
        // Read and parse personal_data.json
        const data = await fs.readFile('./personal_data.json', 'utf8');
        const records = JSON.parse(data);
        
        // Find the record with matching ID
        const record = records.find(r => r.idNumber === id);
        
        if (record) {
            res.json({
                success: true,
                data: record
            });
        } else {
            res.status(404).json({
                success: false,
                error: 'Record not found',
                code: 'NOT_FOUND'
            });
        }
    } catch (error) {
        console.error('Error reading personal info:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to retrieve personal information',
            code: 'INTERNAL_SERVER_ERROR'
        });
    }
});

// Routes
app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

// Serve login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// Serve registration page
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'register.html'));
});

// Serve dashboard (protected route)
app.get('/dashboard', (req, res) => {
    if (!req.session || !req.session.user) {
        console.log('Unauthenticated access to /dashboard, redirecting to /login');
        return res.redirect('/login');
    }
    console.log('Serving dashboard for user:', req.session.user?.username);
    // Set cache control headers to prevent caching of the dashboard
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'), {
        headers: {
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'Surrogate-Control': 'no-store'
        }
    });
});

// API: Register new user
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password, firstName, lastName } = req.body;
        
        // Basic validation
        if (!username || !email || !password || !firstName || !lastName) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        // Check if username or email already exists
        db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], async (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (row) {
                return res.status(400).json({ 
                    error: row.username === username ? 'Username already exists' : 'Email already registered' 
                });
            }
            
            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);
            
            // Insert new user
            db.run(
                'INSERT INTO users (username, email, password, firstName, lastName) VALUES (?, ?, ?, ?, ?)',
                [username, email, hashedPassword, firstName, lastName],
                function(err) {
                    if (err) {
                    }
                    res.status(201).json({ message: 'User registered successfully' });
                }
            );
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// API: Check authentication status
app.get('/api/check-auth', (req, res) => {
    console.log('Checking auth status for session:', req.sessionID);
    console.log('Session user:', req.session.user);
    
    if (req.session.user) {
        res.json({
            authenticated: true,
            user: req.session.user
        });
    } else {
        res.json({
            authenticated: false
        });
    }
});

// API: Login user
app.post('/api/login', (req, res) => {
    console.log('Login attempt:', { username: req.body.username });
    const { username, password } = req.body;
    
    if (!username || !password) {
        console.log('Missing username or password');
        return res.status(400).json({ 
            success: false,
            error: 'Username and password are required' 
        });
    }
    
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            console.error('Database error during login:', err);
            return res.status(500).json({ 
                success: false,
                error: 'Database error' 
            });
        }
        
        if (!user) {
            console.log('User not found:', username);
            return res.status(401).json({ 
                success: false,
                error: 'Invalid username or password' 
            });
        }
        
        try {
            console.log('User found, comparing passwords...');
            const passwordMatch = await bcrypt.compare(password, user.password);
            
            if (!passwordMatch) {
                console.log('Password mismatch for user:', username);
                return res.status(401).json({ 
                    success: false,
                    error: 'Invalid username or password' 
                });
            }
            
            // Store user in session (excluding password)
            const { password: _, ...userWithoutPassword } = user;
            req.session.regenerate((err) => {
                if (err) {
                    console.error('Session regeneration error:', err);
                    return res.status(500).json({ 
                        success: false,
                        error: 'Failed to regenerate session' 
                    });
                }
                
                req.session.user = userWithoutPassword;
                console.log('Login successful for user:', username);
                
                // Save the session before sending the response
                req.session.save((err) => {
                    if (err) {
                        console.error('Session save error:', err);
                        return res.status(500).json({ 
                            success: false,
                            error: 'Failed to save session' 
                        });
                    }
                    
                    console.log('Session after login:', req.session);
                    
            
                    
                    res.json({ 
                        success: true,
                        message: 'Login successful',
                        user: userWithoutPassword,
                        sessionId: req.sessionID
                    });
                });
            });
        } catch (error) {
            console.error('Login error:', error);
            return res.status(500).json({ 
                success: false,
                error: 'Internal server error' 
            });
        }
    });
});

// API: Get personal info by ID
app.get('/api/personal-info/:id', requireAuth, async (req, res) => {
    
    try {
        const idNumber = req.params.id;
        
        // Input validation
        if (!idNumber || !/^\d+$/.test(idNumber)) {
            return res.status(400).json({ error: 'Invalid ID format. Please provide a numeric ID.' });
        }
        
        // Read and parse the JSON file
        const data = await fs.readFile('./personal_data.json', 'utf8');
        const personalData = JSON.parse(data);
        
        // Find the record with the matching ID
        const record = personalData.find(item => item.idNumber === idNumber);
        
        if (!record) {
            return res.status(404).json({ 
                error: 'No record found',
                message: `No personal information found for ID: ${idNumber}`
            });
        }
        
        // Log the access for security/audit purposes
        console.log(`[${new Date().toISOString()}] User ${req.session.user.username} accessed record ${idNumber}`);
        
        // Return the found record
        res.json({
            success: true,
            data: record
        });
        
    } catch (error) {
        console.error('Error reading personal data:', error);
        
        // More specific error handling
        if (error.code === 'ENOENT') {
            return res.status(500).json({ 
                error: 'Data file not found',
                message: 'The personal information database is currently unavailable.'
            });
        } else if (error instanceof SyntaxError) {
            return res.status(500).json({ 
                error: 'Data format error',
                message: 'There was an error processing the personal information database.'
            });
        } else {
            return res.status(500).json({ 
                error: 'Server error',
                message: 'An unexpected error occurred while retrieving the information.'
            });
        }
    }
});

// API: Check if user is authenticated
app.get('/api/check-auth', (req, res) => {
    if (req.session.user) {
        res.json({
            authenticated: true,
            user: req.session.user
        });
    } else {
        res.json({
            authenticated: false
        });
    }
});

// API: Get current user profile
app.get('/api/user/profile', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    // Return user data without sensitive information
    const { password, ...userData } = req.session.user;
    res.json(userData);
});

// API: Update user profile
app.put('/api/user/profile', requireAuth, async (req, res) => {
    
    const { firstName, lastName, email } = req.body;
    
    // Basic validation
    if (!firstName || !lastName || !email) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Please provide a valid email address' });
    }
    
    try {
        // Check if email is already taken by another user
        db.get(
            'SELECT id FROM users WHERE email = ? AND id != ?', 
            [email, req.session.user.id], 
            async (err, row) => {
                if (err) {
                    console.error('Database error checking email:', err);
                    return res.status(500).json({ error: 'Database error' });
                }
                
                if (row) {
                    return res.status(400).json({ error: 'Email is already in use' });
                }
                
                // Update the user in the database
                db.run(
                    'UPDATE users SET firstName = ?, lastName = ?, email = ? WHERE id = ?',
                    [firstName, lastName, email, req.session.user.id],
                    function(err) {
                        if (err) {
                            console.error('Database error updating profile:', err);
                            return res.status(500).json({ error: 'Failed to update profile' });
                        }
                        
                        // Update the session
                        req.session.user = {
                            ...req.session.user,
                            firstName,
                            lastName,
                            email
                        };
                        
                        // Save the session
                        req.session.save(err => {
                            if (err) {
                                console.error('Error saving session:', err);
                                return res.status(500).json({ error: 'Failed to update session' });
                            }
                            
                            res.json({
                                success: true,
                                message: 'Profile updated successfully',
                                user: {
                                    id: req.session.user.id,
                                    username: req.session.user.username,
                                    firstName,
                                    lastName,
                                    email,
                                    theme: req.session.user.theme,
                                    menuPreferences: req.session.user.menuPreferences
                                }
                            });
                        });
                    }
                );
            }
        );
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'An error occurred while updating your profile' });
    }
});

// API: Update user preferences (theme, menu)
app.put('/api/user/preferences', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const { theme, menuPreferences } = req.body;
    const userId = req.session.user.id;
    
    db.run(
        'UPDATE users SET theme = ?, menuPreferences = ? WHERE id = ?',
        [theme, JSON.stringify(menuPreferences), userId],
        function(err) {
            if (err) {
                console.error('Error updating preferences:', err);
                return res.status(500).json({ error: 'Failed to update preferences' });
            }
            
            // Update session with new preferences
            if (theme) req.session.user.theme = theme;
            if (menuPreferences) req.session.user.menuPreferences = menuPreferences;
            
            res.json({ message: 'Preferences updated successfully' });
        }
    );
});

// Password reset request endpoint
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }
        
        // Check if user exists
        db.get('SELECT id, email FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'An error occurred' });
            }
            
            if (!user) {
                // For security, don't reveal if the email exists or not
                return res.json({ message: 'If your email exists in our system, you will receive a password reset link.' });
            }
            
            try {
                // Generate and store reset token
                const token = await generateToken();
                const expiresAt = new Date();
                expiresAt.setHours(expiresAt.getHours() + 1); // 1 hour expiration
                
                // In production, store in database
                passwordResetTokens.set(token, {
                    userId: user.id,
                    email: user.email,
                    expiresAt: expiresAt.toISOString()
                });
                
                // Send reset email
                await sendPasswordResetEmail(user.email, token);
                
                res.json({ message: 'If your email exists in our system, you will receive a password reset link.' });
            } catch (error) {
                console.error('Error generating token:', error);
                res.status(500).json({ error: 'Failed to process your request' });
            }
        });
    } catch (error) {
        console.error('Error in forgot password:', error);
        res.status(500).json({ error: 'An error occurred' });
    }
});

// Reset password endpoint
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        
        if (!token || !newPassword) {
            return res.status(400).json({ error: 'Token and new password are required' });
        }
        
        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters long' });
        }
        
        // In production, verify token from database
        const resetData = passwordResetTokens.get(token);
        
        if (!resetData) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }
        
        // Check if token is expired
        if (new Date(resetData.expiresAt) < new Date()) {
            passwordResetTokens.delete(token);
            return res.status(400).json({ error: 'Token has expired' });
        }
        
        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // Update user's password in database
        db.run(
            'UPDATE users SET password = ? WHERE id = ?',
            [hashedPassword, resetData.userId],
            function(err) {
                if (err) {
                    console.error('Database error updating password:', err);
                    return res.status(500).json({ error: 'Failed to update password' });
                }
                
                if (this.changes === 0) {
                    return res.status(404).json({ error: 'User not found' });
                }
                
                // Delete the used token
                passwordResetTokens.delete(token);
                
                res.json({ message: 'Password reset successful' });
            }
        );
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ error: 'An error occurred' });
    }
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Failed to log out' });
        }
        res.clearCookie('connect.sid');
        res.json({ message: 'Logged out successfully' });
    });
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
    // In production, you might want to use a service like Sentry to log these
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    // In production, you might want to gracefully shut down the server
    // process.exit(1);
});

// Apply error handling middleware (must be after all other middleware and routes)
app.use(notFoundHandler);
app.use(errorHandler);

// Start server
const server = app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
});

// Handle server errors
server.on('error', (error) => {
    if (error.syscall !== 'listen') {
        throw error;
    }

    const bind = typeof PORT === 'string' ? 'Pipe ' + PORT : 'Port ' + PORT;

    // Handle specific listen errors with friendly messages
    switch (error.code) {
        case 'EACCES':
            console.error(bind + ' requires elevated privileges');
            process.exit(1);
            break;
        case 'EADDRINUSE':
            console.error(bind + ' is already in use');
            process.exit(1);
            break;
        default:
            throw error;
    }
});

// Handle graceful shutdown
process.on('SIGINT', () => {
    db.close();
    console.log('Database connection closed');
    process.exit(0);
});
