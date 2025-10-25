// src/services/dynamoService.js
const { PutCommand, GetCommand, QueryCommand, UpdateCommand, DeleteCommand } = require('@aws-sdk/lib-dynamodb');
const { dynamoDB, TABLES } = require('../config/aws');

class DynamoService {
  static async createUser(userData) {
    const command = new PutCommand({
      TableName: TABLES.USERS,
      Item: userData,
      ConditionExpression: 'attribute_not_exists(userId)'
    });
    return await dynamoDB.send(command);
  }

  static async getUserById(userId) {
    const command = new GetCommand({
      TableName: TABLES.USERS,
      Key: { userId }
    });
    const result = await dynamoDB.send(command);
    return result.Item;
  }

  static async getUserByEmail(email) {
    const command = new QueryCommand({
      TableName: TABLES.USERS,
      IndexName: 'EmailIndex',
      KeyConditionExpression: 'email = :email',
      ExpressionAttributeValues: { ':email': email }
    });
    const result = await dynamoDB.send(command);
    return result.Items?.[0];
  }

  static async updateUserScanCount(userId) {
    const command = new UpdateCommand({
      TableName: TABLES.USERS,
      Key: { userId },
      UpdateExpression: 'SET scansUsedThisMonth = scansUsedThisMonth + :inc',
      ExpressionAttributeValues: { ':inc': 1 },
      ReturnValues: 'ALL_NEW'
    });
    const result = await dynamoDB.send(command);
    return result.Attributes;
  }

  static async resetUserScanCount(userId) {
    const command = new UpdateCommand({
      TableName: TABLES.USERS,
      Key: { userId },
      UpdateExpression: 'SET scansUsedThisMonth = :zero, lastResetDate = :now',
      ExpressionAttributeValues: {
        ':zero': 0,
        ':now': new Date().toISOString()
      },
      ReturnValues: 'ALL_NEW'
    });
    const result = await dynamoDB.send(command);
    return result.Attributes;
  }

  static async updateUserProfile(userId, updates) {
    const command = new UpdateCommand({
      TableName: TABLES.USERS,
      Key: { userId },
      UpdateExpression: 'SET #name = :name',
      ExpressionAttributeNames: { '#name': 'name' },
      ExpressionAttributeValues: { ':name': updates.name },
      ReturnValues: 'ALL_NEW'
    });
    const result = await dynamoDB.send(command);
    return result.Attributes;
  }

  static async createScan(scanData) {
    const command = new PutCommand({
      TableName: TABLES.SCANS,
      Item: scanData
    });
    return await dynamoDB.send(command);
  }

  static async getScanById(scanId) {
    const command = new GetCommand({
      TableName: TABLES.SCANS,
      Key: { scanId }
    });
    const result = await dynamoDB.send(command);
    return result.Item;
  }

  static async getUserScans(userId, limit = 50) {
    const command = new QueryCommand({
      TableName: TABLES.SCANS,
      IndexName: 'UserScansIndex',
      KeyConditionExpression: 'userId = :userId',
      ExpressionAttributeValues: { ':userId': userId },
      ScanIndexForward: false,
      Limit: limit
    });
    const result = await dynamoDB.send(command);
    return result.Items || [];
  }

  static async updateScanResults(scanId, scanData) {
    const command = new UpdateCommand({
      TableName: TABLES.SCANS,
      Key: { scanId },
      UpdateExpression: 'SET scanStatus = :status, vulnerabilitiesFound = :count, vulnerabilities = :vulns, summary = :summary, completedAt = :now',
      ExpressionAttributeValues: {
        ':status': scanData.scanStatus,
        ':count': scanData.vulnerabilitiesFound,
        ':vulns': scanData.vulnerabilities,
        ':summary': scanData.summary,
        ':now': new Date().toISOString()
      },
      ReturnValues: 'ALL_NEW'
    });
    const result = await dynamoDB.send(command);
    return result.Attributes;
  }

  static async deleteScan(scanId) {
    const command = new DeleteCommand({
      TableName: TABLES.SCANS,
      Key: { scanId }
    });
    return await dynamoDB.send(command);
  }
}

module.exports = DynamoService;
