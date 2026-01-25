const path = require('path');

module.exports = {
  // Server configuration
  server: {
    port: process.env.PORT || 5000,
    env: process.env.NODE_ENV || 'development',
    apiBaseUrl: process.env.API_BASE_URL || 'http://localhost:5000',
    frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000'
  },

  // Database configuration
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    name: process.env.DB_NAME || 'wenmoon_db',
    user: process.env.DB_USER || 'wenmoon_user',
    password: process.env.DB_PASSWORD || 'SecurePass123!',
    ssl: process.env.DB_SSL === 'true'
  },

  // JWT configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'your_jwt_secret_key_here_change_this',
    expire: process.env.JWT_EXPIRE || '7d',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'your_refresh_secret_here',
    refreshExpire: process.env.JWT_REFRESH_EXPIRE || '30d'
  },

  // Security configuration
  security: {
    encryptionKey: process.env.ENCRYPTION_KEY || 'your_32_char_encryption_key_change_this',
    maxAccountsPerIp: parseInt(process.env.MAX_ACCOUNTS_PER_IP) || 5,
    sessionTimeout: parseInt(process.env.SESSION_TIMEOUT) || 86400,
    rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW) || 15,
    rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX) || 100
  },

  // Email configuration
  email: {
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT) || 587,
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    from: process.env.EMAIL_FROM || 'noreply@wenmoon.com'
  },

  // Redis configuration
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT) || 6379,
    password: process.env.REDIS_PASSWORD || ''
  },

  // External APIs
  external: {
    captchaSecret: process.env.CAPTCHA_SECRET || '',
    web3Provider: process.env.WEB3_PROVIDER || 'https://mainnet.infura.io/v3/your_key',
    telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || '',
    googleClientId: process.env.GOOGLE_CLIENT_ID || '',
    googleClientSecret: process.env.GOOGLE_CLIENT_SECRET || ''
  },

  // File upload configuration
  uploads: {
    directory: path.join(__dirname, '../../uploads'),
    maxFileSize: 10 * 1024 * 1024, // 10MB
    allowedTypes: ['image/jpeg', 'image/png', 'image/gif', 'application/pdf']
  },

  // Logging configuration
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    file: process.env.LOG_FILE || 'logs/app.log'
  },

  // Admin configuration
  admin: {
    email: process.env.ADMIN_EMAIL || 'admin@wenmoon.com',
    password: process.env.ADMIN_PASSWORD || 'admin123'
  },

  // Task configuration
  tasks: {
    defaultPoints: {
      twitter_follow: 50,
      telegram_join: 40,
      watch_ad: 10,
      referral: 100,
      discord_join: 60,
      wallet_connect: 80,
      email_verify: 25,
      daily_login: 5
    }
  }
};
