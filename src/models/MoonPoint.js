const mongoose = require('mongoose');
const logger = require('../utils/logger');

const MoonPointSchema = new mongoose.Schema({
    // User reference
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    
    // Point transaction details
    points: {
        type: Number,
        required: true,
        min: 1
    },
    transactionType: {
        type: String,
        required: true,
        enum: [
            'task_completion',
            'referral',
            'manual_adjustment',
            'bonus',
            'correction',
            'penalty'
        ],
        index: true
    },
    
    // Source reference
    taskId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Task'
    },
    referralId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    
    // Description
    description: {
        type: String,
        required: true
    },
    
    // Verification
    verified: {
        type: Boolean,
        default: true
    },
    verifiedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    verifiedAt: Date,
    
    // Status
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected', 'reversed'],
        default: 'approved'
    },
    rejectionReason: String,
    
    // Audit trail
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    reversedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    reversedAt: Date,
    reversalReason: String,
    
    // Metadata
    metadata: {
        type: Map,
        of: mongoose.Schema.Types.Mixed
    },
    
    // Timestamps
    timestamp: {
        type: Date,
        default: Date.now,
        index: true
    }
}, {
    timestamps: true
});

// Indexes for optimized queries
MoonPointSchema.index({ userId: 1, timestamp: -1 });
MoonPointSchema.index({ transactionType: 1, timestamp: -1 });
MoonPointSchema.index({ status: 1, timestamp: -1 });
MoonPointSchema.index({ taskId: 1 });
MoonPointSchema.index({ referralId: 1 });

// Virtual for point balance after this transaction
MoonPointSchema.virtual('balanceAfter').get(function() {
    // This would be calculated by aggregating all transactions up to this point
    return 0;
});

// Static methods
MoonPointSchema.statics.getUserPointsHistory = async function(userId, limit = 50) {
    return this.find({ userId })
        .sort({ timestamp: -1 })
        .limit(limit)
        .populate('taskId', 'title points category')
        .populate('referralId', 'name email')
        .populate('createdBy', 'name email')
        .lean();
};

MoonPointSchema.statics.getUserPointsSummary = async function(userId) {
    const summary = await this.aggregate([
        {
            $match: {
                userId: mongoose.Types.ObjectId.createFromHexString(userId),
                status: 'approved'
            }
        },
        {
            $group: {
                _id: '$transactionType',
                totalPoints: { $sum: '$points' },
                count: { $sum: 1 }
            }
        },
        {
            $project: {
                type: '$_id',
                totalPoints: 1,
                count: 1,
                _id: 0
            }
        }
    ]);
    
    // Calculate total
    const totalPoints = summary.reduce((sum, item) => sum + item.totalPoints, 0);
    
    return {
        totalPoints,
        breakdown: summary,
        lastUpdated: new Date()
    };
};

MoonPointSchema.statics.getLeaderboardData = async function(days = 30) {
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    
    const leaderboard = await this.aggregate([
        {
            $match: {
                timestamp: { $gte: startDate },
                status: 'approved'
            }
        },
        {
            $group: {
                _id: '$userId',
                totalPoints: { $sum: '$points' },
                lastActivity: { $max: '$timestamp' }
            }
        },
        {
            $lookup: {
                from: 'users',
                localField: '_id',
                foreignField: '_id',
                as: 'user'
            }
        },
        {
            $unwind: '$user'
        },
        {
            $match: {
                'user.status': 'active'
            }
        },
        {
            $project: {
                userId: '$_id',
                name: '$user.name',
                email: '$user.email',
                avatar: '$user.avatar',
                totalPoints: 1,
                lastActivity: 1,
                _id: 0
            }
        },
        { $sort: { totalPoints: -1 } },
        { $limit: 100 }
    ]);
    
    return leaderboard;
};

MoonPointSchema.statics.createPointTransaction = async function(data) {
    const transaction = new this(data);
    await transaction.save();
    
    logger.info(`Moon points transaction created: ${data.points} points for user ${data.userId}`);
    
    return transaction;
};

MoonPointSchema.statics.reverseTransaction = async function(transactionId, reversedBy, reason) {
    const transaction = await this.findById(transactionId);
    if (!transaction) {
        throw new Error('Transaction not found');
    }
    
    if (transaction.status === 'reversed') {
        throw new Error('Transaction already reversed');
    }
    
    transaction.status = 'reversed';
    transaction.reversedBy = reversedBy;
    transaction.reversedAt = new Date();
    transaction.reversalReason = reason;
    
    await transaction.save();
    
    // Create reversal transaction
    const reversalTransaction = new this({
        userId: transaction.userId,
        points: -transaction.points,
        transactionType: 'correction',
        description: `Reversal: ${transaction.description}`,
        status: 'approved',
        createdBy: reversedBy,
        metadata: {
            originalTransaction: transaction._id,
            reversalReason: reason
        }
    });
    
    await reversalTransaction.save();
    
    logger.info(`Moon points transaction reversed: ${transactionId} by ${reversedBy}`);
    
    return {
        original: transaction,
        reversal: reversalTransaction
    };
};

MoonPointSchema.statics.getSystemStats = async function() {
    const stats = await this.aggregate([
        {
            $match: { status: 'approved' }
        },
        {
            $facet: {
                totalPoints: [
                    {
                        $group: {
                            _id: null,
                            total: { $sum: '$points' }
                        }
                    }
                ],
                dailyPoints: [
                    {
                        $match: {
                            timestamp: { 
                                $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) 
                            }
                        }
                    },
                    {
                        $group: {
                            _id: {
                                $dateToString: { format: "%Y-%m-%d", date: "$timestamp" }
                            },
                            points: { $sum: '$points' },
                            transactions: { $sum: 1 }
                        }
                    },
                    { $sort: { _id: 1 } }
                ],
                byType: [
                    {
                        $group: {
                            _id: '$transactionType',
                            points: { $sum: '$points' },
                            transactions: { $sum: 1 }
                        }
                    }
                ],
                topEarnersToday: [
                    {
                        $match: {
                            timestamp: { 
                                $gte: new Date(new Date().setHours(0, 0, 0, 0)) 
                            }
                        }
                    },
                    {
                        $group: {
                            _id: '$userId',
                            points: { $sum: '$points' }
                        }
                    },
                    { $sort: { points: -1 } },
                    { $limit: 10 },
                    {
                        $lookup: {
                            from: 'users',
                            localField: '_id',
                            foreignField: '_id',
                            as: 'user'
                        }
                    },
                    {
                        $unwind: '$user'
                    },
                    {
                        $project: {
                            userId: '$_id',
                            name: '$user.name',
                            points: 1,
                            _id: 0
                        }
                    }
                ]
            }
        }
    ]);
    
    return stats[0] || {};
};

MoonPointSchema.statics.verifyTransaction = async function(transactionId, verifiedBy) {
    const transaction = await this.findByIdAndUpdate(
        transactionId,
        {
            $set: {
                verified: true,
                verifiedBy,
                verifiedAt: new Date()
            }
        },
        { new: true }
    );
    
    if (!transaction) {
        throw new Error('Transaction not found');
    }
    
    logger.info(`Moon points transaction verified: ${transactionId} by ${verifiedBy}`);
    
    return transaction;
};

const MoonPoint = mongoose.model('MoonPoint', MoonPointSchema);

module.exports = MoonPoint;
