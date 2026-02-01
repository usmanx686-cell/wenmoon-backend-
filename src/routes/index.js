const express = require('express');
const router = express.Router();

// Import all route files
const authRoutes = require('./authRoutes');
const userRoutes = require('./userRoutes');
const taskRoutes = require('./taskRoutes');
const moonPointRoutes = require('./moonPointRoutes');
const securityRoutes = require('./securityRoutes');
const adminRoutes = require('./adminRoutes');

// Mount routes
router.use('/auth', authRoutes);
router.use('/users', userRoutes);
router.use('/tasks', taskRoutes);
router.use('/moonpoints', moonPointRoutes);
router.use('/security', securityRoutes);
router.use('/admin', adminRoutes);

// API documentation route
router.get('/docs', (req, res) => {
    res.status(200).json({
        status: 'success',
        data: {
            name: 'WENMOON API',
            version: '1.0.0',
            description: 'WENMOON Airdrop Platform Backend API',
            endpoints: {
                auth: '/api/auth',
                users: '/api/users',
                tasks: '/api/tasks',
                moonpoints: '/api/moonpoints',
                security: '/api/security',
                admin: '/api/admin'
            },
            documentation: 'https://docs.wenmoon.com/api',
            support: 'support@wenmoon.com'
        }
    });
});

module.exports = router;
