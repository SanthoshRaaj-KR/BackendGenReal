const redis = require('redis');

const client = redis.createClient({
  socket: {
    host: process.env.REDIS_HOST || 'otp_redis',
    port: process.env.REDIS_PORT || 6379,
    reconnectStrategy: retries => {
      console.log(`Redis reconnect attempt #${retries}`);
      return Math.min(retries * 50, 1000); // exponential backoff, max 1 sec
    }
  },
  password: process.env.REDIS_PASSWORD || undefined,
});

client.on('error', (err) => console.error('Redis error:', err));
client.on('connect', () => console.log('Connected to Redis'));
client.on('ready', () => console.log('Redis client ready'));
client.on('end', () => console.log('Redis connection closed'));
client.on('reconnecting', () => console.log('Redis reconnecting...'));

// Connect explicitly
(async () => {
  try {
    await client.connect();
  } catch (err) {
    console.error('Failed to connect to Redis:', err);
  }
})();

module.exports = client;
