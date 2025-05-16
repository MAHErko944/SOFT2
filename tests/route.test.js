const mongoose = require("mongoose");
const app = require("../index");
const userModel = require('../models/user.model');
const request = require('supertest');
require("dotenv").config();

// Test users that will be used across tests
const TEST_USERS = {
  signup: { email: "test@example.com" },
  login: { email: "login@test.com" },
  weak: { email: "weak@example.com" },
  mismatch: { email: "aly@g.com" }
};

// Connect to database before tests
beforeAll(async () => {
  await mongoose.connect(process.env.MONGODB_URI);
});

// Clean up test data after all tests
afterAll(async () => {
  // Proper way to delete multiple users
  await userModel.deleteMany({
    email: { 
      $in: Object.values(TEST_USERS).map(user => user.email)
    }
  });
  await mongoose.connection.close();
});

// Set up login test user before that specific test suite
describe('Testing /validateSignUp', () => {
  // Clean up any existing test users before tests
  beforeEach(async () => {
    await userModel.deleteMany({
      email: { $in: [TEST_USERS.signup.email, TEST_USERS.mismatch.email, TEST_USERS.weak.email] }
    });
  });

  it('should return error when confirm password does not match password', async () => {
    const res = await request(app).post('/validateSignUp').send({
      first_name: "aly",
      last_name: "marwan",
      email: TEST_USERS.mismatch.email,
      phone_number: "0111111",
      password: "123123",
      'confirm-password': "diff",
      gender: "Male"
    });
    
    expect(res.status).toBe(200);
    expect(res.text).toContain('Passwords do not match');
  });

  it('should create a new user and redirect to /home', async () => {
    const response = await request(app)
      .post('/validateSignUp')
      .send({
        first_name: 'Test',
        last_name: 'User',
        email: TEST_USERS.signup.email,
        phone_number: '0123456789',
        password: 'Password_123',
        'confirm-password': 'Password_123',
        gender: 'Male'
      });

    expect(response.status).toBe(302);
    expect(response.headers.location).toBe('/');
  });

  it('should detect weak password', async () => {
    const response = await request(app)
      .post('/validateSignUp')
      .send({
        first_name: 'Weak',
        last_name: 'User',
        email: TEST_USERS.weak.email,
        phone_number: '0123456789',
        password: 'password123',
        'confirm-password': 'password123',
        gender: 'Male'
      });
      
    expect(response.status).toBe(200);
expect(response.text).toContain('Password must be at least 8 characters and include uppercase, lowercase, number, and special character');

  });

  it('should throw error when required field is missing', async () => {
    const response = await request(app)
      .post('/validateSignUp')
      .send({
        // Missing first_name intentionally
        last_name: 'User',
        email: 'test@example.com',
        phone_number: '0123456789',
        password: 'Password_123',
        'confirm-password': 'Password_123',
        gender: 'Male'
      });
      
    expect(response.status).toBe(400);
    expect(response.text).toContain('Required field missing');
  });
});

describe('Testing /validateIn', () => {
  // Create login test user before this test suite
  beforeAll(async () => {
    await userModel.deleteMany({ email: TEST_USERS.login.email });
    await userModel.create({
      first_name: 'Login',
      last_name: 'User',
      email: TEST_USERS.login.email,
      phone_number: '0123456789',
      password: 'securepass',
      gender: 'Male'
    });
  });

  it('should return "User not found" if email does not exist', async () => {
    const res = await request(app).post('/validateIn').send({
      email: 'notfound@test.com',
      password: 'anyPass'
    });

    expect(res.status).toBe(200);
    expect(res.text).toContain('User not found');
    expect(res.text).toContain('window.location.href = \'/\';');
  });

  it('should redirect to /home if credentials are correct', async () => {
    const res = await request(app).post('/validateIn').send({
      email: TEST_USERS.login.email,
      password: 'securepass'
    });

    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/home');
  });

  it('should return "Incorrect password" if password is wrong', async () => {
    const res = await request(app).post('/validateIn').send({
      email: TEST_USERS.login.email,
      password: 'wrongpass'
    });

    expect(res.status).toBe(200);
    expect(res.text).toContain('Incorrect password');
    expect(res.text).toContain('window.location.href = \'/\';');
  });

  it('should show error if email is missing', async () => {
    const res = await request(app).post('/validateIn').send({
      email: '',
      password: 'anypass'
    });

    expect(res.status).toBe(400);
    expect(res.text).toContain("Invalid input");
  });

  it('should show error if password is missing', async () => {
    const res = await request(app).post('/validateIn').send({
      email: TEST_USERS.login.email,
      password: ''
    });

    expect(res.status).toBe(400);
    expect(res.text).toContain("Invalid input");
  });

  it('should handle database errors gracefully', async () => {
    // Mock mongoose to throw an error for this test
    const originalFindOne = mongoose.Model.findOne;
    mongoose.Model.findOne = jest.fn().mockImplementationOnce(() => {
      throw new Error('Database error');
    });

    const res = await request(app).post('/validateIn').send({
      email: TEST_USERS.login.email,
      password: 'securepass'
    });

    // Restore original implementation
    mongoose.Model.findOne = originalFindOne;

    expect(res.status).toBe(500);
    expect(res.text).toContain("Internal server error");
  });
});

describe('GET static pages', () => {
  it('should serve signin.html on GET /', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    expect(res.text).toContain('<!DOCTYPE html>');
  });

  it('should serve signup.html on GET /sign', async () => {
    const res = await request(app).get('/sign');
    expect(res.status).toBe(200);
    expect(res.text).toContain('<!DOCTYPE html>');
  });

  it('should require authentication for GET /home', async () => {
    const res = await request(app).get('/home');
    expect(res.status).toBe(401);
  });
  
  it('should access /home with valid session', async () => {
    // This test would require setting up a mock session
    // Example implementation would depend on how your authentication works
    const agent = request.agent(app);
    
    // Login first to get a session
    await agent.post('/validateIn').send({
      email: TEST_USERS.login.email,
      password: 'securepass'
    });
    
    // Now try to access /home with the session
    const res = await agent.get('/home');
    expect(res.status).toBe(200);
    expect(res.text).toContain('<!DOCTYPE html>');
  });
});