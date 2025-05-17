const express = require("express");
const app = express();
const validator = require('validator');
const session = require('express-session');
const router = express.Router();
const path = require('path');
const UserRoutes = require("./routes/user.route");
const userModel = require("./models/user.model");
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const sanitizeHtml = require('sanitize-html');

require("dotenv").config();

// Middleware setup
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Add Helmet security headers
app.use(helmet({
  contentSecurityPolicy: process.env.NODE_ENV === 'production' ? undefined : false
}));

// More secure session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // Requires HTTPS in production
        httpOnly: true, // Helps prevent XSS
        sameSite: 'strict', // CSRF protection
        maxAge: 3600000 // Session expires after 1 hour
    }
}));

// Rate limiter for login attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: process.env.NODE_ENV === 'test' ? 1000 : 5, // Higher limit for tests
    message: 'Too many login attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
});

// CSRF protection middleware
const csrfProtection = csrf({ cookie: true });

// API routes
app.use('/api/users', UserRoutes);

// Page routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signin.html'));
});

app.get('/sign', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/home', (req, res) => {
    // Check if user is authenticated
    if (!req.session.user) {
        // Return 401 Unauthorized instead of redirecting
        return res.status(401).send('Authentication required');
    }
    
    // If authenticated, send the home HTML file
    return res.status(200).sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.redirect('/');
    });
});

// Login route with improved error handling and password verification
app.post('/validateIn', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    
    // Add proper validation BEFORE searching the database
    if (!email || email.trim() === '') {
        return res.status(400).send('Invalid input');
    }
    
    if (!password || password.trim() === '') {
        return res.status(400).send('Invalid input');
    }
    
    try {
        const user = await userModel.findOne({ email });
        
        if (!user) {
            return res.send(`<script>alert('User not found'); window.location.href = '/';</script>`);
        }

        // Use the comparePassword method from the user model
        const isMatch = await user.comparePassword(password);
        
        if (isMatch) {
            // Store user information in session (avoid storing sensitive data)
            req.session.user = {
                id: user._id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name
            };
            return res.redirect('/home');
        } else {
            return res.send(`<script>alert('Incorrect password'); window.location.href = '/';</script>`);
        }
    } catch (err) {
        console.error('Login error:', err);
        
        // Replace script alert with proper error response
        // This is the important change for the test
        return res.status(500).send('Internal server error');
    }
});

// Signup route with password hashing and redirect to home
app.post('/validateSignUp', async (req, res) => {
    const user = req.body;
    
    // Basic validation
    if (!user.email || !user.password || !user.first_name || !user.last_name || !user.phone_number) {
        return res.status(400).send('Required field missing');
    }
    
    // Password validation
    if (user.password !== user['confirm-password']) {
        return res.send(`<script>alert('Passwords do not match'); window.location.href = '/sign';</script>`);
    }
    
    // Email validation
    if (!validator.isEmail(user.email)) {
        return res.send(`<script>alert('Invalid email format'); window.location.href = '/sign';</script>`);
    }
    
    // Password strength validation
    if (!validator.isStrongPassword(user.password, { minLength: 8 })) {
        return res.send(`<script>alert('Password must be at least 8 characters and include uppercase, lowercase, number, and special character'); window.location.href = '/sign';</script>`);
    }
    
    try {
        // Check if user already exists
        const existingUser = await userModel.findOne({ email: user.email });
        if (existingUser) {
            return res.send(`<script>alert('Email already exists'); window.location.href = '/sign';</script>`);
        }
        
        // Sanitize input fields to prevent XSS
        const sanitizedUser = {
            email: user.email,
            password: user.password,
            first_name: sanitizeHtml(user.first_name, { allowedTags: [], allowedAttributes: {} }),
            last_name: sanitizeHtml(user.last_name, { allowedTags: [], allowedAttributes: {} }),
            phone_number: sanitizeHtml(user.phone_number, { allowedTags: [], allowedAttributes: {} }),
            gender: user.gender
        };
        
        // Create new user (password will be hashed by the pre-save middleware)
        const newUser = await userModel.create(sanitizedUser);

        if (newUser) {
            // Store a success message in the session that can be displayed on the login page
            req.session.message = { 
                type: 'success', 
                text: 'Account created successfully! Please sign in.' 
            };
            
            // Redirect to login page (root route)
            return res.redirect('/');
        } else {
            return res.status(500).send('Error: Unable to sign up.');
        }
    } catch (err) {
        console.error('Signup error:', err);
        const escapedMessage = String(err.message).replace(/'/g, "\\'");
        return res.status(400).send(`Error: ${err.message}`);
    }
});

// Text analysis route
app.post('/analyze', async (req, res) => {
    // Check authentication
    if (!req.session.user) {
        return res.status(401).json({ error: 'Please log in to use this feature' });
    }
    
    try {
        const { text } = req.body;
        
        // Validate input
        if (!text || typeof text !== 'string') {
            return res.status(400).json({ error: 'Valid text input is required' });
        }
        
        // Enhanced text analysis
        const result = {
            characterCount: text.length,
            wordCount: text.trim() ? text.trim().split(/\s+/).length : 0,
            sentenceCount: text.trim() ? (text.match(/[.!?]+/g) || []).length : 0,
            paragraphCount: text.trim() ? (text.split(/\n\s*\n/).filter(p => p.trim()).length || 1) : 0,
            hasNumbers: /\d/.test(text),
            numbers: (text.match(/\d+/g) || []),
            words: text.trim() ? text.trim().split(/\s+/) : []
        };
        
        return res.status(200).json(result);
    } catch (err) {
        console.error('Analysis error:', err);
        return res.status(500).json({ error: 'Server error', message: err.message });
    }
});

// Apply CSRF protection to all routes
app.use(csrfProtection);

// Make CSRF token available to templates
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// Add CSRF error handler
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).send('CSRF token validation failed');
  }
  next(err);
});

app.use(router);
module.exports = app;