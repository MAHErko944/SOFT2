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

require("dotenv").config();

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

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
    max: 5,
    message: 'Too many login attempts, please try again later',
});

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
    if (!req.session.user) {
        return res.redirect('/'); // Redirect to login if not authenticated
    }
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
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
    
    // Input validation
    if (typeof email !== 'string' || typeof password !== 'string') {
        return res.status(400).send('Invalid input');
    }

    try {
        // Find user by email
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
        const escapedMessage = String(err.message).replace(/'/g, "\\'");
        return res.send(`<script>alert('Error: ${escapedMessage}'); window.location.href = '/';</script>`);
    }
});

// Signup route with password hashing and redirect to signin
app.post('/validateSignUp', async (req, res) => {
    const user = req.body;
    
    // Basic validation
    if (!user.email || !user.password || !user.first_name || !user.last_name || !user.phone_number) {
        return res.send(`<script>alert('All fields are required'); window.location.href = '/sign';</script>`);
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
        
        // Create new user (password will be hashed by the pre-save middleware)
        const newUser = await userModel.create({
            email: user.email,
            password: user.password, // Don't hash here, let the model middleware handle it
            first_name: user.first_name,
            last_name: user.last_name,
            phone_number: user.phone_number,
            gender: user.gender
        });

        if (newUser) {
            // Success - redirect to signin page as requested
            return res.send(`<script>alert('Account created successfully! Please sign in.'); window.location.href = '/';</script>`);
        } else {
            return res.send(`<script>alert('Error: Unable to sign up.'); window.location.href = '/sign';</script>`);
        }
    } catch (err) {
        console.error('Signup error:', err);
        const escapedMessage = String(err.message).replace(/'/g, "\\'");
        return res.send(`<script>alert('Error: ${escapedMessage}'); window.location.href = '/sign';</script>`);
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

app.use(router);
module.exports = app;