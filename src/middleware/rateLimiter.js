// src/middleware/rateLimiter.js
const { sendError } = require('../utils/response');
const { RATE_LIMIT_WINDOW, RATE_LIMIT_MAX_REQUESTS } = require('../config/constants');

const requestCounts = new Map();

const rateLimiter = (req, res, next) => {
  const userId = req.user?.userId;
  
  if (!userId) {
    return next();
  }

  const now = Date.now();
  const userRequests = requestCounts.get(userId) || [];
  
  // Filter requests within window
  const recentRequests = userRequests.filter(
    timestamp => now - timestamp < RATE_LIMIT_WINDOW
  );

  if (recentRequests.length >= RATE_LIMIT_MAX_REQUESTS) {
    return sendError(res, 'Too many requests. Please try again later.', 429);
  }

  recentRequests.push(now);
  requestCounts.set(userId, recentRequests);

  // Cleanup old entries
  if (requestCounts.size > 10000) {
    const oldestAllowed = now - RATE_LIMIT_WINDOW;
    for (const [id, timestamps] of requestCounts.entries()) {
      const recent = timestamps.filter(t => t > oldestAllowed);
      if (recent.length === 0) {
        requestCounts.delete(id);
      } else {
        requestCounts.set(id, recent);
      }
    }
  }

  next();
};

module.exports = rateLimiter;
