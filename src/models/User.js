const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const logger = require('../utils/logger');

const UserSchema = new mongoose.Schema({
    // Authentication
    email: {
        type: String,
        required: function() { return !this.telegramId && !this.googleId; },
        unique: true,
        sparse: true,
        lowercase: true,
        trim: true,
        validate: {
            validator: function(v) {
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
            },
            message: 'Invalid email format'
        }
    },
    telegramId: {
        type: String,
        unique: true,
        sparse: true,
        index: true
    },
    googleId: {
        type: String,
        unique: true,
        sparse: true,
        index: true
    },
    password: {
        type: String,
        required: function() { return this.email && !this.telegramId && !this.googleId; },
        minlength: 6,
        select: false
    },
    
    // Profile
    name: {
        type: String,
        required: true,
        trim: true,
        minlength: 2,
        maxlength: 50
    },
    avatar: {
        type: String,
        default: null
    },
    
    // Wallet
    walletAddress: {
        type: String,
        sparse: true,
        index: true,
        validate: {
            validator: function(v) {
                return /^0x[a-fA-F0-9]{40}$/.test(v);
            },
            message: 'Invalid Ethereum address'
        }
    },
    walletConnectedAt: Date,
    
    // Moon Points
    moonPoints: {
        type: Number,
        default: 0,
        min: 0
    },
    totalPointsEarned: {
        type: Number,
        default: 0,
        min: 0
    },
    pointsHistory: [{
        points: Number,
        source: String,
        taskId: mongoose.Schema.Types.ObjectId,
        timestamp: { type: Date, default: Date.now }
    }],
    
    // Referral System
    referralCode: {
        type: String,
        unique: true,
        sparse: true,
        index: true
    },
    referredBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    referrals: [{
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        pointsEarned: Number,
        referredAt: Date
    }],
    referralCount: {
        type: Number,
        default: 0
    },
    
    // Tasks
    completedTasks: [{
        taskId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Task'
        },
        completedAt: Date,
        pointsEarned: Number,
        status: {
            type: String,
            enum: ['completed', 'pending_review', 'rejected'],
            default: 'completed'
        }
    }],
    dailyTaskLimit: {
        type: Number,
        default: 10
    },
    tasksCompletedToday: {
        type: Number,
        default: 0
    },
    lastTaskReset: {
        type: Date,
        default: Date.now
    },
    
    // Security
    ipHistory: [{
        ip: String,
        firstSeen: Date,
        lastSeen: Date,
        count: Number,
        country: String,
        city: String,
        isp: String,
        vpn: Boolean,
        proxy: Boolean
    }],
    deviceFingerprint: String,
    deviceHistory: [{
        fingerprint: String,
        firstSeen: Date,
        lastSeen: Date,
        userAgent: String,
        platform: String
    }],
    lastLogin: Date,
    lastActivity: Date,
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: Date,
    twoFactorEnabled: {
        type: Boolean,
        default: false
    },
    twoFactorSecret: {
        type: String,
        select: false
    },
    
    // Verification
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: String,
    verificationExpires: Date,
    emailVerified: {
        type: Boolean,
        default: false
    },
    
    // Risk Management
    riskScore: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    },
    isSuspicious: {
        type: Boolean,
        default: false
    },
    isFlagged: {
        type: Boolean,
        default: false
    },
    flags: [{
        type: String,
        enum: [
            'multiple_accounts', 'unusual_behavior', 'suspicious_ip', 
            'rapid_activity', 'disposable_email', 'vpn_proxy',
            'device_change', 'geo_mismatch', 'pattern_detected'
        ]
    }],
    restrictions: [{
        type: String,
        enum: ['task_limitation', 'withdrawal_hold', 'manual_review']
    }],
    
    // Analytics
    totalLogins: {
        type: Number,
        default: 0
    },
    totalSessions: {
        type: Number,
        default: 0
    },
    
    // Status
    status: {
        type: String,
        enum: ['active', 'suspended', 'banned', 'deleted'],
        default: 'active'
    },
    suspensionReason: String,
    suspensionExpires: Date,
    
    // Metadata
    metadata: {
        type: Map,
        of: mongoose.Schema.Types.Mixed
    }
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Indexes for performance
UserSchema.index({ email: 1 });
UserSchema.index({ telegramId: 1 });
UserSchema.index({ googleId: 1 });
UserSchema.index({ referralCode: 1 });
UserSchema.index({ walletAddress: 1 });
UserSchema.index({ moonPoints: -1 });
UserSchema.index({ riskScore: -1 });
UserSchema.index({ status: 1 });
UserSchema.index({ createdAt: -1 });
UserSchema.index({ 'ipHistory.ip': 1 });
UserSchema.index({ 'deviceHistory.fingerprint': 1 });

// Virtual for total referrals points
UserSchema.virtual('totalReferralPoints').get(function() {
    return this.referrals.reduce((sum, ref) => sum + (ref.pointsEarned || 0), 0);
});

// Virtual for account age
UserSchema.virtual('accountAge').get(function() {
    return Date.now() - this.createdAt;
});

// Pre-save middleware
UserSchema.pre('save', async function(next) {
    // Hash password if modified
    if (this.isModified('password')) {
        try {
            const salt = await bcrypt.genSalt(10);
            this.password = await bcrypt.hash(this.password, salt);
        } catch (error) {
            return next(error);
        }
    }
    
    // Generate referral code for new users
    if (this.isNew && !this.referralCode) {
        this.referralCode = this._id.toString().slice(-8) + crypto.randomBytes(2).toString('hex');
    }
    
    // Reset daily task counter if new day
    if (this.lastTaskReset) {
        const now = new Date();
        const lastReset = new Date(this.lastTaskReset);
        if (now.toDateString() !== lastReset.toDateString()) {
            this.tasksCompletedToday = 0;
            this.lastTaskReset = now;
        }
    }
    
    next();
});

// Methods
UserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

UserSchema.methods.isLocked = function() {
    return this.lockUntil && this.lockUntil > Date.now();
};

UserSchema.methods.incrementLoginAttempts = async function() {
    const updates = { $inc: { loginAttempts: 1 } };
    
    // Lock account after 5 failed attempts for 2 hours
    if (this.loginAttempts + 1 >= 5) {
        updates.$set = { 
            lockUntil: new Date(Date.now() + 2 * 60 * 60 * 1000),
            isFlagged: true
        };
        updates.$push = { flags: 'multiple_failed_logins' };
    }
    
    return this.updateOne(updates);
};

UserSchema.methods.resetLoginAttempts = async function() {
    return this.updateOne({
        $set: { loginAttempts: 0 },
        $unset: { lockUntil: 1 }
    });
};

UserSchema.methods.addIP = async function(ipData) {
    const existingIP = this.ipHistory.find(ip => ip.ip === ipData.ip);
    
    if (existingIP) {
        existingIP.lastSeen = new Date();
        existingIP.count += 1;
        if (ipData.country) existingIP.country = ipData.country;
        if (ipData.city) existingIP.city = ipData.city;
        if (ipData.isp) existingIP.isp = ipData.isp;
        if (ipData.vpn !== undefined) existingIP.vpn = ipData.vpn;
        if (ipData.proxy !== undefined) existingIP.proxy = ipData.proxy;
    } else {
        this.ipHistory.push({
            ip: ipData.ip,
            firstSeen: new Date(),
            lastSeen: new Date(),
            count: 1,
            country: ipData.country,
            city: ipData.city,
            isp: ipData.isp,
            vpn: ipData.vpn || false,
            proxy: ipData.proxy || false
        });
    }
    
    return this.save();
};

UserSchema.methods.addDevice = async function(deviceData) {
    const existingDevice = this.deviceHistory.find(
        device => device.fingerprint === deviceData.fingerprint
    );
    
    if (existingDevice) {
        existingDevice.lastSeen = new Date();
        if (deviceData.userAgent) existingDevice.userAgent = deviceData.userAgent;
        if (deviceData.platform) existingDevice.platform = deviceData.platform;
    } else {
        this.deviceHistory.push({
            fingerprint: deviceData.fingerprint,
            firstSeen: new Date(),
            lastSeen: new Date(),
            userAgent: deviceData.userAgent || '',
            platform: deviceData.platform || ''
        });
    }
    
    return this.save();
};

UserSchema.methods.addPoints = async function(points, source, taskId = null) {
    this.moonPoints += points;
    this.totalPointsEarned += points;
    
    this.pointsHistory.push({
        points,
        source,
        taskId,
        timestamp: new Date()
    });
    
    return this.save();
};

UserSchema.methods.completeTask = async function(taskId, points) {
    // Check daily limit
    if (this.tasksCompletedToday >= this.dailyTaskLimit) {
        throw new Error('Daily task limit reached');
    }
    
    this.completedTasks.push({
        taskId,
        completedAt: new Date(),
        pointsEarned: points,
        status: 'completed'
    });
    
    this.tasksCompletedToday += 1;
    
    await this.addPoints(points, 'task_completion', taskId);
    return this.save();
};

// Static methods
UserSchema.statics.findByEmail = function(email) {
    return this.findOne({ email: email.toLowerCase() });
};

UserSchema.statics.findByReferralCode = function(code) {
    return this.findOne({ referralCode: code });
};

UserSchema.statics.getLeaderboard = async function(limit = 100) {
    return this.find({ status: 'active' })
        .sort({ moonPoints: -1 })
        .limit(limit)
        .select('name moonPoints avatar referralCode')
        .lean();
};

UserSchema.statics.getStats = async function() {
    const stats = await this.aggregate([
        {
            $match: { status: 'active' }
        },
        {
            $group: {
                _id: null,
                totalUsers: { $sum: 1 },
                totalPoints: { $sum: '$moonPoints' },
                avgPoints: { $avg: '$moonPoints' },
                maxPoints: { $max: '$moonPoints' },
                avgRiskScore: { $avg: '$riskScore' }
            }
        }
    ]);
    
    return stats[0] || {
        totalUsers: 0,
        totalPoints: 0,
        avgPoints: 0,
        maxPoints: 0,
        avgRiskScore: 0
    };
};

const User = mongoose.model('User', UserSchema);

module.exports = User;
