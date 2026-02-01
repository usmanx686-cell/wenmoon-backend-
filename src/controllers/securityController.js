const SecurityLog = require('../models/SecurityLog');
const IPLog = require('../models/IPLog');
const BlockedIP = require('../models/BlockedIP');
const User = require('../models/User');
const logger = require('../utils/logger');
const fraudDetection = require('../services/fraudDetection');
const { getIPInfo, getIPReputation } = require('../services/ipService');

// Get security dashboard stats
const getSecurityStats = async (req, res) => {
    try {
        const { days = 7 } = req.query;
        
        // Get security logs statistics
        const securityStats = await SecurityLog.getSecurityStats(parseInt(days));
        
        // Get IP logs statistics
        const ipStats = await IPLog.aggregate([
            {
                $match: {
                    timestamp: { 
                        $gte: new Date(Date.now() - parseInt(days) * 24 * 60 * 60 * 1000) 
                    }
                }
            },
            {
                $facet: {
                    totalRequests: [{ $count: 'count' }],
                    uniqueIPs: [{ $group: { _id: '$ipAddress' } }, { $count: 'count' }],
                    blockedRequests: [
                        { $match: { isBlocked: true } },
                        { $count: 'count' }
                    ],
                    byAction: [
                        {
                            $group: {
                                _id: '$action',
                                count: { $sum: 1 }
                            }
                        },
                        { $sort: { count: -1 } }
                    ],
                    topIPs: [
                        {
                            $group: {
                                _id: '$ipAddress',
                                count: { $sum: 1 },
                                uniqueUsers: { $addToSet: '$userId' }
                            }
                        },
                        {
                            $project: {
                                ipAddress: '$_id',
                                requestCount: '$count',
                                userCount: { $size: '$uniqueUsers' }
                            }
                        },
                        { $sort: { requestCount: -1 } },
                        { $limit: 10 }
                    ]
                }
            }
        ]);
        
        // Get user risk statistics
        const userRiskStats = await User.aggregate([
            {
                $group: {
                    _id: null,
                    totalUsers: { $sum: 1 },
                    suspiciousUsers: { 
                        $sum: { $cond: [{ $eq: ['$isSuspicious', true] }, 1, 0] } 
                    },
                    flaggedUsers: { 
                        $sum: { $cond: [{ $eq: ['$isFlagged', true] }, 1, 0] } 
                    },
                    avgRiskScore: { $avg: '$riskScore' },
                    highRiskUsers: { 
                        $sum: { $cond: [{ $gte: ['$riskScore', 70] }, 1, 0] } 
                    }
                }
            }
        ]);
        
        // Get blocked IPs count
        const blockedIPStats = await BlockedIP.getStats();
        
        // Get fraud detection patterns
        const fraudPatterns = await SecurityLog.aggregate([
            {
                $match: {
                    type: 'fraud_detected',
                    timestamp: { $gte: new Date(Date.now() - parseInt(days) * 24 * 60 * 60 * 1000) }
                }
            },
            {
                $group: {
                    _id: '$details.fraudType',
                    count: { $sum: 1 },
                    avgRiskScore: { $avg: '$riskScore' }
                }
            },
            { $sort: { count: -1 } }
        ]);
        
        res.status(200).json({
            status: 'success',
            data: {
                timeRange: `${days} days`,
                securityLogs: securityStats,
                ipLogs: ipStats[0] || {},
                userRisk: userRiskStats[0] || {},
                blockedIPs: blockedIPStats,
                fraudPatterns,
                summary: {
                    totalRequests: ipStats[0]?.totalRequests[0]?.count || 0,
                    uniqueIPs: ipStats[0]?.uniqueIPs[0]?.count || 0,
                    blockedRequests: ipStats[0]?.blockedRequests[0]?.count || 0,
                    suspiciousUsers: userRiskStats[0]?.suspiciousUsers || 0,
                    activeBlocks: blockedIPStats.activeBlocks || 0
                }
            }
        });
    } catch (error) {
        logger.error('Get security stats error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Check IP reputation
const checkIPReputation = async (req, res) => {
    try {
        const { ip } = req.params;
        
        // Validate IP address
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        if (!ipRegex.test(ip)) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid IP address format'
            });
        }
        
        // Get IP information
        const ipInfo = await getIPInfo(ip);
        
        // Get IP reputation score
        const reputation = await getIPReputation(ip);
        
        // Get IP logs
        const ipLogs = await IPLog.getRecentActivity(ip, 20);
        
        // Check if IP is blocked
        const isBlocked = await BlockedIP.isBlocked(ip);
        
        // Get security logs for this IP
        const securityLogs = await SecurityLog.getIPSecurityHistory(ip, 10);
        
        // Get users associated with this IP
        const users = await User.find({
            'ipHistory.ip': ip
        }).select('name email moonPoints riskScore isSuspicious createdAt').limit(5);
        
        // Analyze IP risk
        const riskAnalysis = await fraudDetection.analyzeIP(ip, ipInfo);
        
        res.status(200).json({
            status: 'success',
            data: {
                ip,
                info: ipInfo,
                reputation,
                isBlocked,
                riskAnalysis,
                stats: {
                    totalRequests: ipLogs.length,
                    uniqueUsers: [...new Set(ipLogs.filter(log => log.userId).map(log => log.userId._id.toString()))].length,
                    blockedRequests: ipLogs.filter(log => log.isBlocked).length
                },
                recentActivity: ipLogs,
                securityLogs,
                associatedUsers: users,
                recommendations: this.generateIPRecommendations(riskAnalysis, users.length)
            }
        });
    } catch (error) {
        logger.error('Check IP reputation error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Block IP address
const blockIP = async (req, res) => {
    try {
        const { ipAddress, reason, duration, blockType = 'manual' } = req.body;
        
        // Validate IP address
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        if (!ipRegex.test(ipAddress)) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid IP address format'
            });
        }
        
        // Check if already blocked
        const existingBlock = await BlockedIP.isBlocked(ipAddress);
        if (existingBlock) {
            return res.status(400).json({
                status: 'error',
                message: 'IP is already blocked',
                existingBlock
            });
        }
        
        // Block the IP
        const blockedIP = await BlockedIP.blockIP(
            ipAddress, 
            reason, 
            duration ? parseInt(duration) : 24 * 60 * 60 * 1000, // Default 24 hours
            {
                blockedBy: req.userId,
                metadata: {
                    blockedVia: 'admin_panel',
                    notes: req.body.notes || ''
                }
            }
        );
        
        // Log the action
        await SecurityLog.create({
            type: 'ip_blocked',
            userId: req.userId,
            ipAddress,
            severity: 'high',
            details: {
                reason,
                duration,
                blockType,
                adminId: req.userId
            }
        });
        
        logger.security.warn(`IP blocked by admin: ${ipAddress} - ${reason}`, {
            adminId: req.userId,
            duration
        });
        
        res.status(200).json({
            status: 'success',
            data: {
                blockedIP,
                message: `IP ${ipAddress} has been blocked`
            }
        });
    } catch (error) {
        logger.error('Block IP error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Unblock IP address
const unblockIP = async (req, res) => {
    try {
        const { ipAddress } = req.params;
        
        // Unblock the IP
        const unblocked = await BlockedIP.unblockIP(ipAddress);
        
        if (!unblocked) {
            return res.status(404).json({
                status: 'error',
                message: 'IP not found or not blocked'
            });
        }
        
        // Log the action
        await SecurityLog.create({
            type: 'admin_action',
            userId: req.userId,
            ipAddress,
            severity: 'info',
            details: {
                action: 'unblock_ip',
                adminId: req.userId
            }
        });
        
        logger.security.info(`IP unblocked by admin: ${ipAddress}`, {
            adminId: req.userId
        });
        
        res.status(200).json({
            status: 'success',
            data: {
                ipAddress,
                unblocked: true,
                message: `IP ${ipAddress} has been unblocked`
            }
        });
    } catch (error) {
        logger.error('Unblock IP error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Get blocked IPs list
const getBlockedIPs = async (req, res) => {
    try {
        const { page = 1, limit = 20, type } = req.query;
        const skip = (page - 1) * limit;
        
        let query = {};
        if (type) {
            query.blockType = type;
        }
        
        // Get active blocked IPs
        const blockedIPs = await BlockedIP.find({
            ...query,
            $or: [
                { blockExpires: { $gt: new Date() } },
                { blockExpires: null },
                { blockType: 'permanent' }
            ]
        })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .populate('blockedBy', 'name email')
        .populate('userIds', 'name email')
        .lean();
        
        // Get total count
        const total = await BlockedIP.countDocuments({
            ...query,
            $or: [
                { blockExpires: { $gt: new Date() } },
                { blockExpires: null },
                { blockType: 'permanent' }
            ]
        });
        
        res.status(200).json({
            status: 'success',
            data: {
                blockedIPs,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / limit)
                }
            }
        });
    } catch (error) {
        logger.error('Get blocked IPs error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Get security logs
const getSecurityLogs = async (req, res) => {
    try {
        const { 
            page = 1, 
            limit = 50, 
            type, 
            severity, 
            userId,
            ipAddress,
            resolved,
            startDate,
            endDate 
        } = req.query;
        
        const skip = (page - 1) * limit;
        
        // Build query
        const query = {};
        
        if (type) query.type = type;
        if (severity) query.severity = severity;
        if (userId) query.userId = userId;
        if (ipAddress) query.ipAddress = ipAddress;
        if (resolved !== undefined) query.resolved = resolved === 'true';
        
        // Date range
        if (startDate || endDate) {
            query.timestamp = {};
            if (startDate) query.timestamp.$gte = new Date(startDate);
            if (endDate) query.timestamp.$lte = new Date(endDate);
        }
        
        // Get logs
        const logs = await SecurityLog.find(query)
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .populate('userId', 'name email')
            .populate('resolvedBy', 'name email')
            .lean();
        
        // Get total count
        const total = await SecurityLog.countDocuments(query);
        
        res.status(200).json({
            status: 'success',
            data: {
                logs,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    pages: Math.ceil(total / limit)
                }
            }
        });
    } catch (error) {
        logger.error('Get security logs error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Get user security report
const getUserSecurityReport = async (req, res) => {
    try {
        const { userId } = req.params;
        
        // Get user
        const user = await User.findById(userId)
            .select('name email moonPoints riskScore isSuspicious isFlagged flags restrictions ipHistory deviceHistory createdAt');
        
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found'
            });
        }
        
        // Get security logs for user
        const securityLogs = await SecurityLog.getUserSecurityHistory(userId, 20);
        
        // Get fraud detection report
        const fraudReport = await fraudDetection.getRiskReport(userId);
        
        // Get IP statistics
        const ipStats = [];
        for (const ip of user.ipHistory) {
            const ipLogs = await IPLog.getIPStats(ip.ip, 24);
            ipStats.push({
                ip: ip.ip,
                firstSeen: ip.firstSeen,
                lastSeen: ip.lastSeen,
                count: ip.count,
                logs: ipLogs
            });
        }
        
        res.status(200).json({
            status: 'success',
            data: {
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    moonPoints: user.moonPoints,
                    riskScore: user.riskScore,
                    isSuspicious: user.isSuspicious,
                    isFlagged: user.isFlagged,
                    flags: user.flags,
                    restrictions: user.restrictions,
                    accountAge: Date.now() - user.createdAt
                },
                fraudReport,
                securityLogs,
                ipStats,
                deviceHistory: user.deviceHistory,
                recommendations: this.generateUserRecommendations(user, fraudReport)
            }
        });
    } catch (error) {
        logger.error('Get user security report error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Mark security log as resolved
const markLogAsResolved = async (req, res) => {
    try {
        const { logId } = req.params;
        const { notes } = req.body;
        
        // Find log
        const log = await SecurityLog.findById(logId);
        if (!log) {
            return res.status(404).json({
                status: 'error',
                message: 'Security log not found'
            });
        }
        
        // Mark as resolved
        const updatedLog = await SecurityLog.markAsResolved(logId, req.userId, notes);
        
        res.status(200).json({
            status: 'success',
            data: {
                log: updatedLog,
                message: 'Security log marked as resolved'
            }
        });
    } catch (error) {
        logger.error('Mark log as resolved error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Get real-time security alerts
const getRealTimeAlerts = async (req, res) => {
    try {
        const { limit = 10 } = req.query;
        
        // Get active alerts
        const alerts = await SecurityLog.getActiveAlerts();
        
        // Get recent blocked attempts
        const recentBlocks = await IPLog.find({
            action: 'blocked_attempt',
            timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) }
        })
        .sort({ timestamp: -1 })
        .limit(5)
        .lean();
        
        // Get high-risk users
        const highRiskUsers = await User.find({
            riskScore: { $gte: 70 },
            status: 'active'
        })
        .select('name email riskScore flags moonPoints createdAt')
        .sort({ riskScore: -1 })
        .limit(5)
        .lean();
        
        res.status(200).json({
            status: 'success',
            data: {
                alerts: alerts.slice(0, limit),
                recentBlocks,
                highRiskUsers,
                summary: {
                    activeAlerts: alerts.length,
                    recentBlocks: recentBlocks.length,
                    highRiskUsers: highRiskUsers.length
                }
            }
        });
    } catch (error) {
        logger.error('Get real-time alerts error:', error);
        res.status(500).json({
            status: 'error',
            message: 'An error occurred'
        });
    }
};

// Helper: Generate IP recommendations
const generateIPRecommendations = (riskAnalysis, userCount) => {
    const recommendations = [];
    
    if (riskAnalysis.riskScore >= 80) {
        recommendations.push('Consider permanent IP blocking');
        recommendations.push('Review all accounts associated with this IP');
    }
    
    if (riskAnalysis.riskFactors.includes('multiple_accounts')) {
        recommendations.push('Investigate potential multi-accounting');
    }
    
    if (riskAnalysis.riskFactors.includes('vpn_proxy')) {
        recommendations.push('Monitor for VPN/proxy usage patterns');
    }
    
    if (userCount > 3) {
        recommendations.push('Implement stricter rate limiting for this IP');
    }
    
    if (riskAnalysis.riskFactors.includes('high_frequency')) {
        recommendations.push('Consider temporary rate limit increase');
    }
    
    return recommendations;
};

// Helper: Generate user recommendations
const generateUserRecommendations = (user, fraudReport) => {
    const recommendations = [];
    
    if (user.riskScore >= 70) {
        recommendations.push('Require additional verification');
        recommendations.push('Limit daily task completion');
        recommendations.push('Manual review of completed tasks');
    }
    
    if (user.flags.includes('multiple_accounts')) {
        recommendations.push('Check for duplicate accounts');
        recommendations.push('Review IP associations');
    }
    
    if (user.flags.includes('rapid_activity')) {
        recommendations.push('Implement activity cooldown periods');
    }
    
    if (user.ipHistory.length > 3) {
        recommendations.push('Monitor for unusual IP changes');
    }
    
    if (user.deviceHistory.length > 2) {
        recommendations.push('Check for device sharing patterns');
    }
    
    return recommendations;
};

module.exports = {
    getSecurityStats,
    checkIPReputation,
    blockIP,
    unblockIP,
    getBlockedIPs,
    getSecurityLogs,
    getUserSecurityReport,
    markLogAsResolved,
    getRealTimeAlerts
};
