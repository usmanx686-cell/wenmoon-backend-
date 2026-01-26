const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: function() { return !this.telegramId && !this.googleId; },
        unique: true,
        sparse: true,
        lowercase: true,
        trim: true
    },
    telegramId: {
        type: String,
        unique: true,
        sparse: true
    },
    googleId: {
        type: String,
        unique: true,
        sparse: true
    },
    password: {
        type: String,
        required: function() { return this.email && !this.telegramId && !this.googleId; },
        minlength: 6,
        select: false
    },
    name: {
        type: String,
        required: true,
        trim: true
    },
    walletAddress: {
        type: String,
        sparse: true,
        index: true
    },
    moonPoints: {
        type: Number,
        default: 0,
        min: 0
    },
    referralCode: {
        type: String,
        unique: true,
        sparse: true
    },
    referredBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    referrals: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    completedTasks: [{
        taskId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Task'
        },
        completedAt: Date,
        pointsEarned: Number
    }],
    // Security fields
    ipHistory: [{
        ip: String,
        firstSeen: Date,
        lastSeen: Date,
        count: Number
    }],
    deviceFingerprint: String,
    lastLogin: Date,
    loginAttempts: {
        type: Number,
        default: 0
    },
    lockUntil: Date,
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: String,
    verificationExpires: Date,
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
    flags: [{
        type: String,
        enum: ['multiple_accounts', 'unusual_behavior', 'suspicious_ip', 'rapid_activity']
    }]
}, {
    timestamps: true
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Generate referral code before saving
UserSchema.pre('save', async function(next) {
    if (this.isNew && !this.referralCode) {
        this.referralCode = this._id.toString().slice(-8) + Math.random().toString(36).substr(2, 4);
    }
    next();
});

// Method to compare passwords
UserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Method to check if account is locked
UserSchema.methods.isLocked = function() {
    return this.lockUntil && this.lockUntil > Date.now();
};

// Method to increment login attempts
UserSchema.methods.incLoginAttempts = function() {
    // If we have a previous lock that has expired, reset to 1
    if (this.lockUntil && this.lockUntil < Date.now()) {
        return this.updateOne({
            $set: { loginAttempts: 1 },
            $unset: { lockUntil: 1 }
        });
    }
    
    // Otherwise increment
    const updates = { $inc: { loginAttempts: 1 } };
    
    // Lock the account if we've reached max attempts
    if (this.loginAttempts + 1 >= 5) {
        updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 hours
    }
    
    return this.updateOne(updates);
};

const User = mongoose.model('User', UserSchema);

module.exports = User;
