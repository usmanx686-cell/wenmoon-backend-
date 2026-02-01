const mongoose = require('mongoose');
const NodeCache = require('node-cache');
const logger = require('../utils/logger');

// Cache for blocked IPs (1 minute TTL, auto-refresh)
const blockedCache = new NodeCache({ stdTTL: 60, checkperiod: 30 });

const BlockedIPSchema = new mongoose.Schema({
    ipAddress: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    ipVersion: {
        type: Number,
        enum: [4, 6],
        default: 4
    },
    reason: {
        type: String,
        required: true
    },
    blockType: {
        type: String,
        enum: ['temporary', 'permanent', 'manual', 'automatic'],
        default: 'temporary'
    },
    blockedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    userIds: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    violationCount: {
        type: Number,
        default: 1
    },
    blockExpires: {
        type: Date,
        index: true
    },
    metadata: {
        type: Map,
        of: mongoose.Schema.Types.Mixed
    }
}, {
    timestamps: true
});

// Indexes
BlockedIPSchema.index({ blockExpires: 1 });
BlockedIPSchema.index({ createdAt: -1 });
BlockedIPSchema.index({ violationCount: -1 });

// Pre-save middleware to update cache
BlockedIPSchema.pre('save', function(next) {
    // Invalidate cache for this IP
    blockedCache.del(this.ipAddress);
    next();
});

// Static methods
BlockedIPSchema.statics.isBlocked = async function(ip) {
    // Check cache first
    const cached = blockedCache.get(ip);
    if (cached !== undefined) {
        return cached;
    }
    
    const blockedIP = await this.findOne({
        ipAddress: ip,
        $or: [
            { blockExpires: { $gt: new Date() } },
            { blockExpires: null },
            { blockType: 'permanent' }
        ]
    }).lean();
    
    // Cache the result (null if not blocked)
    blockedCache.set(ip, blockedIP || null);
    
    return blockedIP || null;
};

BlockedIPSchema.statics.blockIP = async function(ip, reason, duration = null, options = {}) {
    const blockExpires = duration ? new Date(Date.now() + duration) : null;
    const blockType = duration === 0 ? 'permanent' : 'temporary';
    
    let blockedIP = await this.findOne({ ipAddress: ip });
    
    if (blockedIP) {
        // Update existing block
        blockedIP.reason = reason;
        blockedIP.blockType = blockType;
        blockedIP.blockExpires = blockExpires;
        blockedIP.violationCount += 1;
        
        if (options.userId && !blockedIP.userIds.includes(options.userId)) {
            blockedIP.userIds.push(options.userId);
        }
        
        if (options.metadata) {
            blockedIP.metadata = new Map([
                ...Array.from(blockedIP.metadata.entries()),
                ...Object.entries(options.metadata)
            ]);
        }
    } else {
        // Create new block
        blockedIP = new this({
            ipAddress: ip,
            reason,
            blockType,
            blockExpires,
            blockedBy: options.blockedBy,
            userIds: options.userId ? [options.userId] : [],
            metadata: options.metadata ? new Map(Object.entries(options.metadata)) : new Map()
        });
    }
    
    await blockedIP.save();
    
    logger.warn(`IP blocked: ${ip} - ${reason} (${blockType})`);
    
    return blockedIP;
};

BlockedIPSchema.statics.unblockIP = async function(ip) {
    const result = await this.deleteOne({ ipAddress: ip });
    
    // Clear from cache
    blockedCache.del(ip);
    
    if (result.deletedCount > 0) {
        logger.info(`IP unblocked: ${ip}`);
        return true;
    }
    
    return false;
};

BlockedIPSchema.statics.getActiveBlocks = async function() {
    return this.find({
        $or: [
            { blockExpires: { $gt: new Date() } },
            { blockExpires: null },
            { blockType: 'permanent' }
        ]
    })
    .sort({ createdAt: -1 })
    .lean();
};

BlockedIPSchema.statics.cleanupExpiredBlocks = async function() {
    const result = await this.deleteMany({
        blockExpires: { $lt: new Date() },
        blockType: { $ne: 'permanent' }
    });
    
    if (result.deletedCount > 0) {
        logger.info(`Cleaned up ${result.deletedCount} expired IP blocks`);
    }
    
    // Clear entire cache since we don't know which IPs were removed
    blockedCache.flushAll();
    
    return result;
};

BlockedIPSchema.statics.getStats = async function() {
    const stats = await this.aggregate([
        {
            $facet: {
                totalBlocks: [
                    { $count: 'count' }
                ],
                activeBlocks: [
                    {
                        $match: {
                            $or: [
                                { blockExpires: { $gt: new Date() } },
                                { blockExpires: null },
                                { blockType: 'permanent' }
                            ]
                        }
                    },
                    { $count: 'count' }
                ],
                byType: [
                    {
                        $group: {
                            _id: '$blockType',
                            count: { $sum: 1 }
                        }
                    }
                ],
                byReason: [
                    {
                        $group: {
                            _id: '$reason',
                            count: { $sum: 1 }
                        }
                    },
                    { $sort: { count: -1 } },
                    { $limit: 10 }
                ]
            }
        }
    ]);
    
    return {
        totalBlocks: stats[0]?.totalBlocks[0]?.count || 0,
        activeBlocks: stats[0]?.activeBlocks[0]?.count || 0,
        byType: stats[0]?.byType || [],
        topReasons: stats[0]?.byReason || []
    };
};

BlockedIPSchema.statics.autoBlockIP = async function(ip, violationData) {
    const { reason, userId, violationType, severity = 'medium' } = violationData;
    
    let duration = 24 * 60 * 60 * 1000; // 24 hours default
    
    // Adjust duration based on severity and violation count
    const existingBlock = await this.findOne({ ipAddress: ip });
    const violationCount = existingBlock ? existingBlock.violationCount + 1 : 1;
    
    if (violationCount >= 5) {
        duration = 7 * 24 * 60 * 60 * 1000; // 1 week
    } else if (violationCount >= 3) {
        duration = 3 * 24 * 60 * 60 * 1000; // 3 days
    }
    
    if (severity === 'high') {
        duration *= 2;
    } else if (severity === 'critical') {
        duration = 0; // Permanent
    }
    
    const metadata = {
        violationType,
        severity,
        violationCount,
        autoBlocked: true,
        timestamp: new Date().toISOString()
    };
    
    return this.blockIP(ip, reason, duration, {
        userId,
        metadata
    });
};

const BlockedIP = mongoose.model('BlockedIP', BlockedIPSchema);

module.exports = BlockedIP;
