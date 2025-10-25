// src/controllers/userController.js
const DynamoService = require('../services/dynamoService');
const { sendSuccess, sendError } = require('../utils/response');

class UserController {
  static async getProfile(req, res) {
    try {
      const user = await DynamoService.getUserById(req.user.userId);
      
      if (!user) {
        return sendError(res, 'User not found', 404);
      }

      delete user.passwordHash;

      return sendSuccess(res, { user });

    } catch (error) {
      console.error('Get profile error:', error);
      return sendError(res, error.message, 500);
    }
  }

  static async getUsage(req, res) {
    try {
      const user = await DynamoService.getUserById(req.user.userId);
      
      if (!user) {
        return sendError(res, 'User not found', 404);
      }

      const usage = {
        accountType: user.accountType,
        scansUsedThisMonth: user.scansUsedThisMonth,
        scanLimit: user.scanLimit,
        scansRemaining: user.scanLimit - user.scansUsedThisMonth,
        lastResetDate: user.lastResetDate
      };

      return sendSuccess(res, { usage });

    } catch (error) {
      console.error('Get usage error:', error);
      return sendError(res, error.message, 500);
    }
  }

  static async updateProfile(req, res) {
    try {
      const { name } = req.body;

      if (!name) {
        return sendError(res, 'Name is required', 400);
      }

      const updated = await DynamoService.updateUserProfile(req.user.userId, { name });

      delete updated.passwordHash;

      return sendSuccess(res, {
        message: 'Profile updated successfully',
        user: updated
      });

    } catch (error) {
      console.error('Update profile error:', error);
      return sendError(res, error.message, 500);
    }
  }
}

module.exports = UserController;
