const mongoose = require('mongoose');
const logger = require('../utils/logger');

const SecurityLogSchema = new mongoose.Schema({
    // Event identification
    type: {
        type: String,
        required: true,
        enum: [
            'signup', 'login', 'logout', 'password_reset',
            'email_verification', 'wallet_connected', 'task_completed',
            'referral_used', 'account_updated', 'account_deleted',
            'suspicious_activity', 'bot_detected', 'ip_blocked',
            'rate_limit_exceeded', 'fraud_detected', 'admin_action',
            'system_alert', 'api_request', 'security_scan'
        ],
        index: true
    },
    
    // User information
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        index: true
    },
    userEmail: String,
    userName: String,
    
    // IP and location
    ipAddress: {
        type: String,
        index: true
    },
    country: String,
    city: String,
    isp: String,
    vpn: Boolean,
    proxy: Boolean,
    
    // Device information
    userAgent: String,
    deviceFingerprint: String,
    platform: String,
    browser: String,
    os: String,
    
    // Event details
    action: String,
    endpoint: String,
    method: String,
    statusCode: Number,
    requestId: String,
    sessionId: String,
    
    // Risk assessment
    riskScore: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    },
    severity: {
        type: String,
        enum: ['info', 'low', 'medium', 'high', 'critical'],
        default: 'info'
    },
    riskFactors: [String],
    
    // Additional details
    details: mongoose.Schema.Types.Mixed,
    
    // Response information
    responseTime: Number, // in milliseconds
    responseSize: Number, // in bytes
    
    // Resolution
    resolved: {
        type: Boolean,
        default: false
    },
    resolvedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    resolvedAt: Date,
    resolutionNotes: String,
    
    // Metadata
    metadata: mongoose.Schema.Types.Mixed,
    
    // Timestamps
    timestamp: {
        type: Date,
        default: Date.now,
        index: true,
        expires: '90d' // Auto-delete after 90 days
    }
}, {
    timestamps: true
});

// Indexes for optimized queries
SecurityLogSchema.index({ type: 1, timestamp: -1 });
SecurityLogSchema.index({ userId: 1, timestamp: -1 });
SecurityLogSchema.index({ ipAddress: 1, timestamp: -1 });
SecurityLogSchema.index({ severity: 1, timestamp: -1 });
SecurityLogSchema.index({ resolved: 1, timestamp: -1 });

// Pre-save middleware to add metadata
SecurityLogSchema.pre('save', function(next) {
    if (this.isNew) {
        // Generate request ID if not provided
        if (!this.requestId) {
            this.requestId = require('crypto').randomBytes(8).toString('hex');
        }
        
        // Set severity based on risk score
        if (!this.severity && this.riskScore > 0) {
            if (this.riskScore >= 80) {
                this.severity = 'critical';
            } else if (this.riskScore >= 60) {
                this.severity = 'high';
            } else if (this.riskScore >= 40) {
                this.severity = 'medium';
            } else if (this.riskScore >= 20) {
                this.severity = 'low';
            }
        }
    }
    next();
});

// Static methods
SecurityLogSchema.statics.logSecurityEvent = async function(eventData) {
    try {
        const log = new this(eventData);
        await log.save();
        
        // If severity is high or critical, trigger alert
        if (['high', 'critical'].includes(log.severity)) {
            this.triggerAlert(log);
        }
        
        return log;
    } catch (error) {
        logger.error('Failed to log security event:', error);
        return null;
    }
};

SecurityLogSchema.statics.triggerAlert = async function(log) {
    // In production, this would trigger email/SMS/Webhook alerts
    // For now, just log it
    
    logger.security[log.severity](`Security alert: ${log.type}`, {
        userId: log.userId,
        ipAddress: log.ipAddress,
        riskScore: log.riskScore,
        details: log.details
    });
};

SecurityLogSchema.statics.getSecurityStats = async function(days = 7) {
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    
    const stats = await this.aggregate([
        {
            $match: {
                timestamp: { $gte: startDate }
            }
        },
        {
            $facet: {
                totalEvents: [
                    { $count: 'count' }
                ],
                byType: [
                    {
                        $group: {
                            _id: '$type',
                            count: { $sum: 1 },
                            avgRiskScore: { $avg: '$riskScore' }
                        }
                    },
                    { $sort: { count: -1 } }
                ],
                bySeverity: [
                    {
                        $group: {
                            _id: '$severity',
                            count: { $sum: 1 }
                        }
                    }
                ],
                byCountry: [
                    {
                        $group: {
                            _id: '$country',
                            count: { $sum: 1 },
                            uniqueIPs: { $addToSet: '$ipAddress' }
                        }
                    },
                    {
                        $project: {
                            country: '$_id',
                            count: 1,
                            uniqueIPCount: { $size: '$uniqueIPs' }
                        }
                    },
                    { $sort: { count: -1 } },
                    { $limit: 10 }
                ],
                unresolvedAlerts: [
                    {
                        $match: {
                            severity: { $in: ['high', 'critical'] },
                            resolved: false
                        }
                    },
                    { $count: 'count' }
                ],
                hourlyDistribution: [
                    {
                        $group: {
                            _id: {
                                hour: { $hour: '$timestamp' },
                                type: '$type'
                            },
                            count: { $sum: 1 }
                        }
                    },
                    {
                        $group: {
                            _id: '$_id.hour',
                            types: {
                                $push: {
                                    type: '$_id.type',
                                    count: '$count'
                                }
                            },
                            total: { $sum: '$count' }
                        }
                    },
                    { $sort: { _id: 1 } }
                ]
            }
        }
    ]);
    
    return stats[0] || {};
};

SecurityLogSchema.statics.getUserSecurityHistory = async function(userId, limit = 50) {
    return this.find({ userId })
        .sort({ timestamp: -1 })
        .limit(limit)
        .select('type timestamp ipAddress country severity riskScore details')
        .lean();
};

SecurityLogSchema.statics.getIPSecurityHistory = async function(ipAddress, limit = 50) {
    return this.find({ ipAddress })
        .sort({ timestamp: -1 })
        .limit(limit)
        .select('type timestamp userId severity riskScore details country')
        .populate('userId', 'name email')
        .lean();
};

SecurityLogSchema.statics.markAsResolved = async function(logId, resolvedBy, notes = '') {
    return this.findByIdAndUpdate(
        logId,
        {
            $set: {
                resolved: true,
                resolvedBy,
                resolvedAt: new Date(),
                resolutionNotes: notes
            }
        },
        { new: true }
    );
};

SecurityLogSchema.statics.getActiveAlerts = async function(severity = ['high', 'critical']) {
    return this.find({
        severity: { $in: severity },
        resolved: false,
        timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    })
    .sort({ timestamp: -1 })
    .populate('userId', 'name email')
    .lean();
};

SecurityLogSchema.statics.cleanupOldLogs = async function(days = 90) {
    const cutoffDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    
    // Archive resolved logs older than cutoff
    const result = await this.deleteMany({
        timestamp: { $lt: cutoffDate },
        resolved: true,
        severity: { $ne: 'critical' }
    });
    
    if (result.deletedCount > 0) {
        logger.info(`Cleaned up ${result.deletedCount} old security logs`);
    }
    
    return result;
};

SecurityLogSchema.statics.createSignupLog = async function(user, ipInfo, riskScore = 0) {
    return this.logSecurityEvent({
        type: 'signup',
        userId: user._id,
        userEmail: user.email,
        userName: user.name,
        ipAddress: ipInfo.ip,
        country: ipInfo.country,
        city: ipInfo.city,
        isp: ipInfo.isp,
        vpn: ipInfo.vpn || false,
        proxy: ipInfo.proxy || false,
        userAgent: ipInfo.userAgent,
        deviceFingerprint: user.deviceFingerprint,
        riskScore,
        details: {
            method: user.googleId ? 'google' : user.telegramId ? 'telegram' : 'email',
            pointsAwarded: 50
        }
    });
};

SecurityLogSchema.statics.createLoginLog = async function(user, ipInfo, success = true, failureReason = null) {
    return this.logSecurityEvent({
        type: 'login',
        userId: user._id,
        userEmail: user.email,
        userName: user.name,
        ipAddress: ipInfo.ip,
        country: ipInfo.country,
        city: ipInfo.city,
        userAgent: ipInfo.userAgent,
        riskScore: success ? 0 : 30,
        severity: success ? 'info' : 'medium',
        details: {
            success,
            failureReason,
            loginAttempts: user.loginAttempts,
            accountLocked: user.isLocked()
        }
    });
};

const SecurityLog = mongoose.model('SecurityLog', SecurityLogSchema);

module.exports = SecurityLog;
