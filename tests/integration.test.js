const mongoose = require("mongoose");
const app = require("../index");
const userModel = require('../models/user.model');
const request = require('supertest');
const bcrypt = require('bcrypt');

require("dotenv").config();

// Mock session middleware for testing protected routes
jest.mock('express-session', () => {
  return () => (req, res, next) => {
    req.session = {
      user: {
        id: '60f5fdd2bcf86cd799439012', // Mock user ID for testing
        email: 'test@example.com',
        role: 'admin' // Admin role to access all endpoints
      }
    };
    next();
  };
});

// Test data for reuse
const testUsers = {
  validUser1: {
    first_name: "Alice",
    last_name: "Smith",
    email: "alice@test.com",
    phone_number: "01234567890",
    password: "SecurePass123!",
    gender: "Female"
  },
  validUser2: {
    first_name: "Bob",
    last_name: "Jones",
    email: "bob@test.com",
    phone_number: "09876543210",
    password: "AnotherPass456!",
    gender: "Male"
  },
  invalidUser: {
    first_name: "Invalid",
    // Missing required fields
  }
};

// Setup database connection before running tests
beforeAll(async () => {
  // Use a test database
  const mongoURI = process.env.TEST_MONGODB_URI || process.env.MONGODB_URI;
  await mongoose.connect(mongoURI);
  
  // Clear test data before starting
  await userModel.deleteMany({
    email: { $in: [testUsers.validUser1.email, testUsers.validUser2.email] }
  });
});

// Close database connection after all tests
afterAll(async () => {
  // Clean up test data
  await userModel.deleteMany({
    email: { $in: [testUsers.validUser1.email, testUsers.validUser2.email] }
  });
  await mongoose.connection.close();
});

// This helps maintain test isolation
beforeEach(async () => {
  // Nothing needed here as we clean up in specific tests
});

describe('User API - CRUD Operations', () => {
  
  // Test creating users
  describe('POST /api/users - Create User', () => {
    it('should create a new user with valid data', async () => {
      const response = await request(app)
        .post('/api/users')
        .send(testUsers.validUser1);
      
      expect(response.status).toBe(201);
      expect(response.body).toHaveProperty('email', testUsers.validUser1.email);
      expect(response.body).not.toHaveProperty('password'); // Password should not be returned
    });
    
    it('should reject creation with missing required fields', async () => {
      const response = await request(app)
        .post('/api/users')
        .send(testUsers.invalidUser);
      
      expect(response.status).toBe(400);
    });
    
    it('should reject duplicate email', async () => {
      // First create a user
      await request(app)
        .post('/api/users')
        .send(testUsers.validUser2);
      
      // Try to create another user with the same email
      const response = await request(app)
        .post('/api/users')
        .send({...testUsers.validUser2, first_name: "Different"});
      
      expect(response.status).toBe(409);
    });
  });
  
  // Test retrieving users
  describe('GET /api/users - Retrieve Users', () => {
    let userId;
    
    beforeEach(async () => {
      // Create a test user to retrieve
      const user = await userModel.create({
        ...testUsers.validUser1,
        password: await bcrypt.hash(testUsers.validUser1.password, 10)
      });
      userId = user._id.toString();
    });
    
    afterEach(async () => {
      // Clean up after each test
      await userModel.findByIdAndDelete(userId);
    });
    
    it('should retrieve all users', async () => {
      const response = await request(app).get('/api/users');
      
      expect(response.status).toBe(200);
      expect(Array.isArray(response.body)).toBe(true);
    });
    
    it('should retrieve a specific user by ID', async () => {
      const response = await request(app).get(`/api/users/${userId}`);
      
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('email', testUsers.validUser1.email);
    });
    
    it('should return 404 for non-existent user ID', async () => {
      // Use a valid MongoDB ObjectId that doesn't exist
      const nonExistentId = '60f5fdd2bcf86cd799439011';
      const response = await request(app).get(`/api/users/${nonExistentId}`);
      
      expect(response.status).toBe(404);
    });
    
    it('should return 400 for invalid user ID format', async () => {
      const invalidId = 'not-an-id';
      const response = await request(app).get(`/api/users/${invalidId}`);
      
      expect(response.status).toBe(400);
    });
  });
  
  // Test updating users
  describe('PATCH /api/users/:id - Update User', () => {
    let userId;
    
    beforeEach(async () => {
      // Create a test user to update
      const user = await userModel.create({
        ...testUsers.validUser1,
        password: await bcrypt.hash(testUsers.validUser1.password, 10)
      });
      userId = user._id.toString();
    });
    
    afterEach(async () => {
      // Clean up after each test
      await userModel.findByIdAndDelete(userId);
    });
    
    it('should update user details', async () => {
      const updates = {
        first_name: "UpdatedName",
        gender: "Other"
      };
      
      const response = await request(app)
        .patch(`/api/users/${userId}`)
        .send(updates);
      
      expect(response.status).toBe(200);
      expect(response.body.first_name).toBe(updates.first_name);
      expect(response.body.gender).toBe(updates.gender);
    });
    
    it('should return 404 when updating non-existent user', async () => {
      const nonExistentId = '60f5fdd2bcf86cd799439011';
      const updates = { first_name: "Nobody" };
      
      const response = await request(app)
        .patch(`/api/users/${nonExistentId}`)
        .send(updates);
      
      expect(response.status).toBe(404);
    });
    
    it('should return 400 for invalid ID format', async () => {
      const invalidId = 'not-an-id';
      const updates = { first_name: "Invalid" };
      
      const response = await request(app)
        .patch(`/api/users/${invalidId}`)
        .send(updates);
      
      expect(response.status).toBe(400);
    });
    
    it('should hash password when updating password field', async () => {
      const newPassword = "NewSecurePass456!";
      const updates = { password: newPassword };
      
      const response = await request(app)
        .patch(`/api/users/${userId}`)
        .send(updates);
      
      expect(response.status).toBe(200);
      
      // Verify password was hashed
      const updatedUser = await userModel.findById(userId);
      const passwordMatches = await bcrypt.compare(newPassword, updatedUser.password);
      expect(passwordMatches).toBe(true);
    });
  });
  
  // Test deleting users
  describe('DELETE /api/users/:id - Delete User', () => {
    let userId;
    
    beforeEach(async () => {
      // Create a test user to delete
      const user = await userModel.create({
        ...testUsers.validUser2,
        password: await bcrypt.hash(testUsers.validUser2.password, 10)
      });
      userId = user._id.toString();
    });
    
    it('should delete a user', async () => {
      const response = await request(app).delete(`/api/users/${userId}`);
      
      expect(response.status).toBe(200);
      
      // Verify user was deleted
      const deletedUser = await userModel.findById(userId);
      expect(deletedUser).toBeNull();
    });
    
    it('should return 404 when deleting non-existent user', async () => {
      const nonExistentId = '60f5fdd2bcf86cd799439011';
      
      const response = await request(app).delete(`/api/users/${nonExistentId}`);
      
      expect(response.status).toBe(404);
    });
    
    it('should return 400 for invalid ID format', async () => {
      const invalidId = 'not-an-id';
      
      const response = await request(app).delete(`/api/users/${invalidId}`);
      
      expect(response.status).toBe(400);
    });
  });
  
  // Test authentication routes
  describe('Authentication Routes', () => {
    let testUserEmail = 'authtest@example.com';
    let testUserPassword = 'AuthTest123!';
    
    beforeEach(async () => {
      // Create a test user for authentication tests
      const user = {
        email: testUserEmail,
        password: testUserPassword,
        first_name: 'Auth',
        last_name: 'Test',
        phone_number: '1234567890',
        gender: 'Male'
      };
      
      await request(app).post('/validateSignUp').send({
        ...user,
        'confirm-password': testUserPassword
      });
    });
    
    afterEach(async () => {
      // Clean up test user
      await userModel.deleteMany({ email: testUserEmail });
    });
    
    it('should sign in with valid credentials', async () => {
      const response = await request(app)
        .post('/validateIn')
        .send({
          email: testUserEmail,
          password: testUserPassword
        });
      
      // Since our endpoint redirects rather than returning JSON,
      // we'll check for a 302 redirect status or 200 status
      expect([200, 302]).toContain(response.status);
    });
    
    it('should reject sign in with incorrect password', async () => {
      const response = await request(app)
        .post('/validateIn')
        .send({
          email: testUserEmail,
          password: 'WrongPassword123!'
        });
      
      // Our endpoint sends a script with an alert message
      expect(response.text).toContain('Incorrect password');
    });
    
    it('should reject sign in with non-existent user', async () => {
      const response = await request(app)
        .post('/validateIn')
        .send({
          email: 'nonexistent@example.com',
          password: 'SomePassword123!'
        });
      
      expect(response.text).toContain('User not found');
    });
  });
});