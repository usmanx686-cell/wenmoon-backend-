const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const userAgent = require('express-useragent');
const logger = require('./utils/logger');

// Security middleware
const securityMiddleware = require('./middleware/security');
const rateLimitMiddleware = require('./middleware/rateLimit');
const ipLimitMiddleware = require('./middleware/ipLimit');

// Routes
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const taskRoutes = require('./routes/taskRoutes');
const securityRoutes = require('./routes/securityRoutes');

const app = express();

// Trust proxy for IP detection
app.set('trust proxy', true);

// Security headers
app.use(helmet());

// Enable CORS
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:8080',
    credentials: true
}));

// Body parser
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// User agent parsing
app.use(userAgent.express());

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Data sanitization against XSS
app.use(xss());

// Security middleware
app.use(securityMiddleware.detectBot);
app.use(securityMiddleware.validateRequest);

// Rate limiting
app.use('/api/auth', rateLimitMiddleware.authLimiter);
app.use('/api/tasks', rateLimitMiddleware.taskLimiter);

// IP limiting middleware
app.use('/api/auth/signup', ipLimitMiddleware.checkIPLimit);
app.use('/api/auth/social', ipLimitMiddleware.checkIPLimit);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/tasks', taskRoutes);
app.use('/api/security', securityRoutes);

// Health check
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'healthy',
        timestamp: new Date().toISOString()
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        status: 'error',
        message: 'Route not found'
    });
});

// Global error handler
app.use((err, req, res, next) => {
    logger.error('Global error handler:', err);
    
    res.status(err.statusCode || 500).json({
        status: 'error',
        message: err.message || 'Internal server error',
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
});

module.exports = app;
