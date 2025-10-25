// src/controllers/authController.js
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const DynamoService = require('../services/dynamoService');
const { sendSuccess, sendError } = require('../utils/response');
const { FREE_SCAN_LIMIT, JWT_EXPIRY } = require('../config/constants');

class AuthController {
  static async register(req, res) {
    try {
      const { email, password, name } = req.body;

      if (!email || !password || password.length < 6) {
        return sendError(res, 'Email and password (min 6 chars) required', 400);
      }

      const existingUser = await DynamoService.getUserByEmail(email);
      if (existingUser) {
        return sendError(res, 'User already exists', 409);
      }

      const passwordHash = await bcrypt.hash(password, 10);
      const userId = uuidv4();
      
      const userData = {
        userId,
        email,
        name: name || email.split('@')[0],
        passwordHash,
        accountType: 'free',
        scansUsedThisMonth: 0,
        scanLimit: FREE_SCAN_LIMIT,
        createdAt: new Date().toISOString(),
        lastResetDate: new Date().toISOString()
      };

      await DynamoService.createUser(userData);

      const token = jwt.sign(
        { userId, email },
        process.env.JWT_SECRET,
        { expiresIn: JWT_EXPIRY }
      );

      delete userData.passwordHash;

      return sendSuccess(res, {
        message: 'User registered successfully',
        token,
        user: userData
      }, 201);

    } catch (error) {
      console.error('Register error:', error);
      return sendError(res, error.message, 500);
    }
  }

  static async login(req, res) {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return sendError(res, 'Email and password required', 400);
      }

      const user = await DynamoService.getUserByEmail(email);
      if (!user) {
        return sendError(res, 'Invalid credentials', 401);
      }

      const validPassword = await bcrypt.compare(password, user.passwordHash);
      if (!validPassword) {
        return sendError(res, 'Invalid credentials', 401);
      }

      const token = jwt.sign(
        { userId: user.userId, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: JWT_EXPIRY }
      );

      delete user.passwordHash;

      return sendSuccess(res, {
        message: 'Login successful',
        token,
        user
      });

    } catch (error) {
      console.error('Login error:', error);
      return sendError(res, error.message, 500);
    }
  }

  static async verifyToken(req, res) {
    try {
      const user = await DynamoService.getUserById(req.user.userId);
      
      if (!user) {
        return sendError(res, 'User not found', 404);
      }

      delete user.passwordHash;

      return sendSuccess(res, {
        valid: true,
        user
      });

    } catch (error) {
      console.error('Verify token error:', error);
      return sendError(res, error.message, 500);
    }
  }
}

module.exports = AuthController;
