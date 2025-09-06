// src/utils/activityLogger.js
const fs = require('fs');
const path = require('path');
const { getDeviceInfo, sanitizeUser } = require('./helpers');

const logFile = path.join(__dirname, '../../logs/entries.log');

const logActivity = (req, user, action = 'ACTION') => {
  try {
    const deviceInfo = getDeviceInfo(req);
    const cleanUser = sanitizeUser(user);

    const entry = {
      timestamp: new Date().toISOString(),
      action,
      ip: deviceInfo.ip,
      userAgent: deviceInfo.userAgent,
      user: cleanUser,
    };

    fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
  } catch (err) {
    console.error('Failed to write log entry:', err);
  }
};

module.exports = { logActivity };
