// src/controllers/scanController.js
const { v4: uuidv4 } = require('uuid');
const DynamoService = require('../services/dynamoService');
const PythonService = require('../services/pythonService');
const { sendSuccess, sendError } = require('../utils/response');

class ScanController {
  static async submitScan(req, res) {
    try {
      const { targetUrl } = req.body;
      const userId = req.user.userId;

      if (!targetUrl || !targetUrl.startsWith('http')) {
        return sendError(res, 'Valid URL required (http:// or https://)', 400);
      }

      const user = await DynamoService.getUserById(userId);

      // Check month reset
      const lastReset = new Date(user.lastResetDate);
      const now = new Date();
      if (lastReset.getMonth() !== now.getMonth() || 
          lastReset.getFullYear() !== now.getFullYear()) {
        await DynamoService.resetUserScanCount(userId);
        user.scansUsedThisMonth = 0;
      }

      // Check scan limit
      if (user.accountType === 'free' && user.scansUsedThisMonth >= user.scanLimit) {
        return sendError(res, 'Scan limit reached. Upgrade to continue.', 429);
      }

      const scanId = uuidv4();
      const scanData = {
        scanId,
        userId,
        targetUrl,
        scanStatus: 'running',
        vulnerabilitiesFound: 0,
        vulnerabilities: [],
        createdAt: new Date().toISOString()
      };

      await DynamoService.createScan(scanData);
      await DynamoService.updateUserScanCount(userId);

      try {
        const scanResult = await PythonService.executeScan(targetUrl);
        
        await DynamoService.updateScanResults(scanId, scanResult);
        
        const scansLeft = user.scanLimit - user.scansUsedThisMonth - 1;

        return sendSuccess(res, {
          message: 'Scan completed successfully',
          scanId,
          scan: {
            ...scanResult,
            scanId
          },
          scansLeft: Math.max(0, scansLeft)
        }, 200);

      } catch (scanError) {
        console.error('Scan failed:', scanError);
        
        await DynamoService.updateScanResults(scanId, {
          scanStatus: 'failed',
          vulnerabilitiesFound: 0,
          vulnerabilities: [],
          summary: { total: 0, bySeverity: {}, riskScore: 0 }
        });
        
        return sendError(res, `Scan failed: ${scanError.message}`, 500);
      }

    } catch (error) {
      console.error('Submit scan error:', error);
      return sendError(res, error.message, 500);
    }
  }

  static async getScanResult(req, res) {
    try {
      const { scanId } = req.params;
      const userId = req.user.userId;

      const scan = await DynamoService.getScanById(scanId);

      if (!scan) {
        return sendError(res, 'Scan not found', 404);
      }

      if (scan.userId !== userId) {
        return sendError(res, 'Unauthorized', 403);
      }

      return sendSuccess(res, { scan });

    } catch (error) {
      console.error('Get scan error:', error);
      return sendError(res, error.message, 500);
    }
  }

  static async getScanHistory(req, res) {
    try {
      const userId = req.user.userId;
      const limit = parseInt(req.query.limit) || 50;

      const scans = await DynamoService.getUserScans(userId, limit);

      return sendSuccess(res, {
        scans,
        total: scans.length
      });

    } catch (error) {
      console.error('Get history error:', error);
      return sendError(res, error.message, 500);
    }
  }

  static async deleteScan(req, res) {
    try {
      const { scanId } = req.params;
      const userId = req.user.userId;

      const scan = await DynamoService.getScanById(scanId);

      if (!scan) {
        return sendError(res, 'Scan not found', 404);
      }

      if (scan.userId !== userId) {
        return sendError(res, 'Unauthorized', 403);
      }

      await DynamoService.deleteScan(scanId);

      return sendSuccess(res, {
        message: 'Scan deleted successfully'
      });

    } catch (error) {
      console.error('Delete scan error:', error);
      return sendError(res, error.message, 500);
    }
  }
}

module.exports = ScanController;
