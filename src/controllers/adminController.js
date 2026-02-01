const User = require('../models/User');
const Task = require('../models/Task');
const IPLog = require('../models/IPLog');
const SecurityLog = require('../models/SecurityLog');
const BlockedIP = require('../models/BlockedIP');
const Whitelist = require('../models/Whitelist');
const logger = require('../utils/logger');
const fraudDetection = require('../services/fraudDetection');
const emailService = require('../services/emailService');
const { getIPInfo } = require('../services/ipService');

// Get admin dashboard statistics
const getAdminDashboard = async (req, res) => {
    try {
        // Get user statistics
        const userStats = await User.aggregate([
            {
                $facet: {
                    totalByStatus: [
                        {
                            $group: {
                                _id: '$status',
                                count: { $sum: 1 }
                            }
                        }
                    ],
                    dailySignups: [
                        {
                            $match: {
                                createdAt: { 
                                    $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) 
                                }
                            }
                        },
                        {
                            $group: {
                                _id: {
                                    $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
                                },
                                count: { $sum: 1 }
                            }
                        },
                        { $sort: { _id: 1 } }
                    ],
                    byAuthMethod: [
                        {
                            $group: {
                                _id: {
                                    $cond: [
                                        { $ne: ['$googleId', null] },
                                        'google',
                                        { $cond: [
                                            { $ne: ['$telegramId', null] },
                                            'telegram',
                                            'email'
                                        ]}
                                    ]
                                },
                                count: { $sum: 1 }
                            }
                        }
                    ],
                    pointsDistribution: [
                        {
                            $bucket: {
                                groupBy: "$moonPoints",
                                boundaries: [0, 100, 500, 1000, 5000, 10000, Infinity],
                                default: "10000+",
                                output: {
                                    count: { $sum: 1 },
                                    avgPoints: { $avg: "$moonPoints" }
                                }
                            }
                        }
                    ]
                }
            }
        ]);
        
        // Get task statistics
        const taskStats = await Task.aggregate([
            {
                $facet: {
                    totalByStatus: [
                        {
                            $group: {
                                _id: '$status',
                                count: { $sum: 1 },
                                totalPoints: { $sum: '$points' }
                            }
                        }
                    ],
                    byCategory: [
                        {
                            $group: {
                                _id: '$category',
                                count: { $sum: 1 },
                                totalPoints: { $sum: '$points' }
                            }
                        }
                    ],
                    completionStats: [
                        {
                            $lookup: {
                                from: 'users',
                                let: { taskId: '$_id' },
                                pipeline: [
                                    {
                                        $match: {
                                            $expr: {
                                                $in: ['$$taskId', '$completedTasks.taskId']
                                            }
                                        }
                                    },
                                    { $count: 'count' }
                                ],
                                as: 'completions'
                            }
                        },
                        {
                            $project: {
                                title: 1,
                                points: 1,
                                completions: { $arrayElemAt: ['$completions.count', 0] } || 0
                            }
                        },
                        { $sort: { completions: -1 } },
                        { $limit: 10 }
                    ]
                }
            }
        ]);
        
        // Get security statistics
        const securityStats = await SecurityLog.aggregate([
            {
                $match: {
                    timestamp: { 
                        $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) 
                    }
                }
            },
            {
                $facet: {
                    bySeverity: [
                        {
                            $group: {
                                _id: '$severity',
                                count: { $sum: 1 }
                            }
                        }
                    ],
                    byType: [
                        {
                            $group: {
                                _id: '$type',
                                count: { $sum: 1 }
                            }
                        },
                        { $sort: { count: -1 } },
                        { $limit: 10 }
                    ],
                    hourlyActivity: [
                        {
                            $group: {
                                _id: {
                                    $hour: '$timestamp'
                                },
                                count: { $sum: 1 }
                            }
                        },
                        { $sort: { _id: 1 } }
                    ]
                }
            }
        ]);
        
        // Get system statistics
        const systemStats = {
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            nodeVersion: process.version,
            environment: process.env.NODE_ENV,
            timestamp: new Date().toISOString()
        };
        
        res.status(200).json({
            status: 'success',
            data: {
                users: userStats[0] || {},
                tasks: taskStats[0] || {},
                security: securityStats[0] || {},
                system: systemStats,
                summary: {
                    totalUsers: await User.countDocuments(),
                    activeUsers: await User.countDocuments({ status: 'active' }),
                    totalTasks: await Task.countDocuments(),
                    activeTasks: await Task.countDocuments({ status: 'active' }),
                    blockedIPs: await BlockedIP.countDocuments(),
                    securityEvents24h: await SecurityLog.countDocuments({ 
                        timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } 
                    })
                }
            }
        });
    } catch (error) {
        logger.error('Get admin dashboard error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Get user management list
const getUsers = async (req, res) => {
    try {
        const { 
            page = 1, 
            limit = 20, 
            status, 
            search,
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;
        
        const skip = (page - 1) * limit;
        
        // Build query
        const query = {};
        
        if (status) query.status = status;
        
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { walletAddress: { $regex: search, $options: 'i' } },
                { referralCode: { $regex: search, $options: 'i' } }
            ];
        }
        
        // Build sort
        const sort = {};
        sort[sortBy] = sortOrder === 'desc' ? -1 : 1;
        
        // Get users
        const users = await User.find(query)
            .sort(sort)
            .skip(skip)
            .limit(parseInt(limit))
            .select('-password -twoFactorSecret -verificationToken')
            .populate('referredBy', 'name email')
            .lean();
        
        // Get total count
        const total = await User.countDocuments(query);
        
        res.status(200).json({
            status: 'success',
            data: {
                users,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / limit)
                }
            }
        });
    } catch (error) {
        logger.error('Get users error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Update user status
const updateUserStatus = async (req, res) => {
    try {
        const { userId } = req.params;
        const { status, reason, suspensionExpires } = req.body;
        
        // Validate status
        const validStatuses = ['active', 'suspended', 'banned'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid status'
            });
        }
        
        // Find user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }
        
        // Store old status
        const oldStatus = user.status;
        
        // Update user
        user.status = status;
        
        if (status === 'suspended') {
            user.suspensionReason = reason || 'Administrative action';
            user.suspensionExpires = suspensionExpires ? new Date(suspensionExpires) : null;
        } else {
            user.suspensionReason = undefined;
            user.suspensionExpires = undefined;
        }
        
        await user.save();
        
        // Log the action
        await SecurityLog.create({
            type: 'admin_action',
            userId: req.userId,
            severity: 'high',
            details: {
                action: 'update_user_status',
                targetUserId: userId,
                oldStatus,
                newStatus: status,
                reason,
                adminId: req.userId
            }
        });
        
        // Send notification to user if suspended or banned
        if (status === 'suspended' || status === 'banned') {
            await emailService.sendSecurityAlert(user, 'account_locked', {
                reason: reason || 'Administrative action',
                expires: suspensionExpires
            });
        }
        
        logger.audit('User status updated', req.userId, {
            targetUserId: userId,
            oldStatus,
            newStatus: status,
            reason
        });
        
        res.status(200).json({
            status: 'success',
            data: {
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    status: user.status,
                    suspensionReason: user.suspensionReason,
                    suspensionExpires: user.suspensionExpires
                },
                message: `User status updated to ${status}`
            }
        });
    } catch (error) {
        logger.error('Update user status error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Get user details
const getUserDetails = async (req, res) => {
    try {
        const { userId } = req.params;
        
        // Get user with all details
        const user = await User.findById(userId)
            .select('-password -twoFactorSecret -verificationToken')
            .populate('completedTasks.taskId')
            .populate('referrals.userId', 'name email moonPoints')
            .populate('referredBy', 'name email')
            .lean();
        
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }
        
        // Get security logs for user
        const securityLogs = await SecurityLog.find({ userId })
            .sort({ timestamp: -1 })
            .limit(20)
            .lean();
        
        // Get IP logs for user
        const ipLogs = await IPLog.find({ userId })
            .sort({ timestamp: -1 })
            .limit(20)
            .lean();
        
        // Get fraud detection report
        const fraudReport = await fraudDetection.getRiskReport(userId);
        
        res.status(200).json({
            status: 'success',
            data: {
                user,
                security: {
                    logs: securityLogs,
                    ipHistory: ipLogs,
                    fraudReport
                }
            }
        });
    } catch (error) {
        logger.error('Get user details error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Add manual points to user
const addManualPoints = async (req, res) => {
    try {
        const { userId } = req.params;
        const { points, reason } = req.body;
        
        if (!points || points <= 0) {
            return res.status(400).json({
                status: 'error',
                message: 'Points must be a positive number'
            });
        }
        
        if (!reason || reason.trim().length < 5) {
            return res.status(400).json({
                status: 'error',
                message: 'Reason is required (minimum 5 characters)'
            });
        }
        
        // Find user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }
        
        // Add points
        await user.addPoints(parseInt(points), 'manual_adjustment');
        
        // Log the action
        await SecurityLog.create({
            type: 'admin_action',
            userId: req.userId,
            severity: 'medium',
            details: {
                action: 'add_manual_points',
                targetUserId: userId,
                points: parseInt(points),
                reason,
                adminId: req.userId,
                newBalance: user.moonPoints
            }
        });
        
        logger.audit('Manual points added', req.userId, {
            targetUserId: userId,
            points: parseInt(points),
            reason,
            newBalance: user.moonPoints
        });
        
        res.status(200).json({
            status: 'success',
            data: {
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email
                },
                pointsAdded: parseInt(points),
                newBalance: user.moonPoints,
                reason
            }
        });
    } catch (error) {
        logger.error('Add manual points error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Task management
const createTask = async (req, res) => {
    try {
        const taskData = req.body;
        
        // Create task
        const task = await Task.create(taskData);
        
        // Log the action
        await SecurityLog.create({
            type: 'admin_action',
            userId: req.userId,
            severity: 'info',
            details: {
                action: 'create_task',
                taskId: task._id,
                taskTitle: task.title,
                adminId: req.userId
            }
        });
        
        logger.audit('Task created', req.userId, {
            taskId: task._id,
            taskTitle: task.title,
            points: task.points
        });
        
        res.status(201).json({
            status: 'success',
            data: { task }
        });
    } catch (error) {
        logger.error('Create task error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

const updateTask = async (req, res) => {
    try {
        const { taskId } = req.params;
        const updateData = req.body;
        
        // Find and update task
        const task = await Task.findByIdAndUpdate(
            taskId,
            updateData,
            { new: true, runValidators: true }
        );
        
        if (!task) {
            return res.status(404).json({
                status: 'error',
                message: 'Task not found'
            });
        }
        
        // Log the action
        await SecurityLog.create({
            type: 'admin_action',
            userId: req.userId,
            severity: 'info',
            details: {
                action: 'update_task',
                taskId: task._id,
                taskTitle: task.title,
                updates: updateData,
                adminId: req.userId
            }
        });
        
        logger.audit('Task updated', req.userId, {
            taskId: task._id,
            taskTitle: task.title,
            updates: updateData
        });
        
        res.status(200).json({
            status: 'success',
            data: { task }
        });
    } catch (error) {
        logger.error('Update task error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// System configuration
const getSystemConfig = async (req, res) => {
    try {
        // This would typically load configuration from database
        // For now, return environment-based config
        
        const config = {
            security: {
                ipLimiting: process.env.IP_LIMITING_ENABLED === 'true',
                maxUsersPerIP: parseInt(process.env.MAX_USERS_PER_IP || '5'),
                captchaEnabled: process.env.CAPTCHA_ENABLED === 'true',
                fraudDetection: process.env.FRAUD_DETECTION_ENABLED === 'true'
            },
            tasks: {
                dailyLimit: parseInt(process.env.DAILY_TASK_LIMIT || '10'),
                autoApprove: process.env.AUTO_APPROVE_TASKS === 'true'
            },
            email: {
                enabled: process.env.EMAIL_ENABLED === 'true',
                fromEmail: process.env.EMAIL_FROM
            },
            tokenomics: {
                totalSupply: process.env.TOTAL_SUPPLY,
                airdropAllocation: process.env.AIRDROP_ALLOCATION,
                tokenSymbol: process.env.TOKEN_SYMBOL
            }
        };
        
        res.status(200).json({
            status: 'success',
            data: { config }
        });
    } catch (error) {
        logger.error('Get system config error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Run system maintenance
const runMaintenance = async (req, res) => {
    try {
        const { tasks } = req.body;
        
        const results = {
            cleanedIPLogs: 0,
            cleanedSecurityLogs: 0,
            expiredBlocks: 0,
            userCleanup: 0
        };
        
        // Run requested maintenance tasks
        if (tasks.includes('cleanup_old_logs')) {
            // Clean up old IP logs (auto-expires based on schema)
            results.cleanedIPLogs = 'Auto-expired based on TTL';
            
            // Clean up old security logs
            const securityResult = await SecurityLog.cleanupOldLogs(30);
            results.cleanedSecurityLogs = securityResult.deletedCount || 0;
        }
        
        if (tasks.includes('cleanup_expired_blocks')) {
            const blockResult = await BlockedIP.cleanupExpiredBlocks();
            results.expiredBlocks = blockResult.deletedCount || 0;
        }
        
        if (tasks.includes('cleanup_unverified_users')) {
            // Delete unverified users older than 7 days
            const cutoffDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
            const userResult = await User.deleteMany({
                isVerified: false,
                emailVerified: false,
                createdAt: { $lt: cutoffDate },
                status: 'active'
            });
            results.userCleanup = userResult.deletedCount || 0;
        }
        
        // Log the maintenance
        await SecurityLog.create({
            type: 'system_alert',
            userId: req.userId,
            severity: 'info',
            details: {
                action: 'system_maintenance',
                tasks,
                results,
                adminId: req.userId
            }
        });
        
        logger.audit('System maintenance run', req.userId, {
            tasks,
            results
        });
        
        res.status(200).json({
            status: 'success',
            data: {
                tasks,
                results,
                message: 'Maintenance completed successfully'
            }
        });
    } catch (error) {
        logger.error('Run maintenance error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Export data
const exportData = async (req, res) => {
    try {
        const { type, format = 'json' } = req.query;
        
        let data;
        
        switch (type) {
            case 'users':
                data = await User.find({})
                    .select('-password -twoFactorSecret -verificationToken')
                    .lean();
                break;
                
            case 'tasks':
                data = await Task.find({}).lean();
                break;
                
            case 'security_logs':
                const { startDate, endDate } = req.query;
                const query = {};
                
                if (startDate) query.timestamp = { $gte: new Date(startDate) };
                if (endDate) query.timestamp = { ...query.timestamp, $lte: new Date(endDate) };
                
                data = await SecurityLog.find(query)
                    .populate('userId', 'name email')
                    .lean();
                break;
                
            default:
                return res.status(400).json({
                    status: 'error',
                    message: 'Invalid export type'
                });
        }
        
        // Log the export
        await SecurityLog.create({
            type: 'admin_action',
            userId: req.userId,
            severity: 'medium',
            details: {
                action: 'data_export',
                exportType: type,
                format,
                recordCount: data.length,
                adminId: req.userId
            }
        });
        
        logger.audit('Data exported', req.userId, {
            type,
            format,
            recordCount: data.length
        });
        
        // Set response headers for download
        const filename = `wenmoon_${type}_${new Date().toISOString().split('T')[0]}.${format}`;
        
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        
        if (format === 'csv') {
            res.setHeader('Content-Type', 'text/csv');
            // Convert to CSV (simplified)
            const csv = convertToCSV(data);
            return res.send(csv);
        } else {
            res.setHeader('Content-Type', 'application/json');
            return res.json({
                status: 'success',
                data,
                metadata: {
                    exportedAt: new Date().toISOString(),
                    recordCount: data.length,
                    type,
                    format
                }
            });
        }
    } catch (error) {
        logger.error('Export data error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Helper: Convert to CSV
const convertToCSV = (data) => {
    if (!data || data.length === 0) return '';
    
    const headers = Object.keys(data[0]).join(',');
    const rows = data.map(item => 
        Object.values(item).map(val => 
            typeof val === 'object' ? JSON.stringify(val) : val
        ).join(',')
    );
    
    return [headers, ...rows].join('\n');
};

module.exports = {
    getAdminDashboard,
    getUsers,
    updateUserStatus,
    getUserDetails,
    addManualPoints,
    createTask,
    updateTask,
    getSystemConfig,
    runMaintenance,
    exportData
};
