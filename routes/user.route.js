const express = require("express");
const router = express.Router();
const {
    getUsers,
    getUser,
    createUser,
    updateUser,
    deleteUser,
} = require("../controllers/user.controller");

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
    if (req.session && req.session.user) {
        return next();
    }
    return res.status(401).json({ message: "Unauthorized" });
};

// Middleware to check if user is admin
const isAdmin = (req, res, next) => {
    if (req.session && req.session.user && req.session.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ message: "Forbidden: Admin access required" });
};

// Public routes
router.post("/", createUser); // Allow user registration without authentication

// Protected routes
router.get('/', isAuthenticated, isAdmin, getUsers); // Only admins can get all users
router.get('/:id', isAuthenticated, getUser); // Users can only access their own data
router.patch("/:id", isAuthenticated, updateUser);
router.delete('/:id', isAuthenticated, isAdmin, deleteUser); // Only admins can delete users

module.exports = router;