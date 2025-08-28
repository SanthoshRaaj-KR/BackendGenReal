const crypto = require('crypto');

const getDeviceInfo = (req) => {
  return {
    userAgent: req.get('User-Agent'),
    ip: req.ip || req.connection.remoteAddress,
    timestamp: new Date(),
  };
};

const generateRandomString = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

const sanitizeUser = (user) => {
  const { password, twoFactorSecret, ...sanitizedUser } = user.toJSON ? user.toJSON() : user;
  return sanitizedUser;
};

module.exports = {
  getDeviceInfo,
  generateRandomString,
  sanitizeUser,
};