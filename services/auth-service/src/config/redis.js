const redis = require('redis');

let client;

if (process.env.REDIS_URL) {
  // Render or cloud provider with connection URL
  client = redis.createClient({
    url: process.env.REDIS_URL,
    socket: {
      reconnectStrategy: retries => {
        console.log(`Redis reconnect attempt #${retries}`);
        return Math.min(retries * 50, 1000);
      }
    }
  });
  console.log("🔌 Using cloud Redis instance");
} else {
  // Local Docker Compose or bare metal
  client = redis.createClient({
    socket: {
      host: process.env.REDIS_HOST || 'otp_redis',
      port: process.env.REDIS_PORT || 6379,
      reconnectStrategy: retries => {
        console.log(`Redis reconnect attempt #${retries}`);
        return Math.min(retries * 50, 1000);
      }
    },
    password: process.env.REDIS_PASSWORD || undefined,
  });
  console.log("🛠️ Using local Redis instance (otp_redis)");
}

client.on('error', (err) => console.error('Redis error:', err));
client.on('connect', () => console.log('Connected to Redis'));
client.on('ready', () => console.log('Redis client ready'));
client.on('end', () => console.log('Redis connection closed'));
client.on('reconnecting', () => console.log('Redis reconnecting...'));

(async () => {
  try {
    await client.connect();
  } catch (err) {
    console.error('Failed to connect to Redis:', err);
  }
})();

module.exports = client;
