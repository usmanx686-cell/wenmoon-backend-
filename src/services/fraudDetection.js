const User = require('../models/User');
const IPLog = require('../models/IPLog');
const SecurityLog = require('../models/SecurityLog');
const logger = require('../utils/logger');
const securityConfig = require('../config/security');
const crypto = require('crypto');

class FraudDetection {
    constructor() {
        this.rules = [
            this.checkMultipleAccounts,
            this.checkRapidActivity,
            this.checkSuspiciousEmail,
            this.checkUnusualTiming,
            this.checkDeviceFingerprint,
            this.checkBehaviorPatterns,
            this.checkReferralAbuse,
            this.checkTaskCompletionPatterns
        ];
        
        this.disposableEmailDomains = this.loadDisposableDomains();
    }
    
    loadDisposableDomains() {
        return [
            'tempmail.com', 'mailinator.com', 'guerrillamail.com',
            '10minutemail.com', 'yopmail.com', 'trashmail.com',
            'fakeinbox.com', 'throwawaymail.com', 'getairmail.com',
            'maildrop.cc', 'spamgourmet.com', 'guerrillamail.biz',
            'sharklasers.com', 'guerrillamail.org', 'guerrillamail.net',
            'grr.la', 'pokemail.net', 'spam4.me'
        ];
    }
    
    async analyzeSignup(data) {
        let totalScore = 0;
        const flags = [];
        const details = {};
        
        for (const rule of this.rules) {
            try {
                const result = await rule(data);
                totalScore += result.score || 0;
                if (result.flag) {
                    flags.push(result.flag);
                }
                if (result.details) {
                    Object.assign(details, result.details);
                }
            } catch (error) {
                logger.error(`Fraud detection rule error (${rule.name}):`, error);
            }
        }
        
        // Cap at 100
        totalScore = Math.min(totalScore, 100);
        
        return { 
            totalScore, 
            flags, 
            details,
            level: this.getRiskLevel(totalScore)
        };
    }
    
    async analyzeIP(ip, ipInfo = {}) {
        const analysis = {
            ip,
            riskScore: 0,
            riskFactors: [],
            recommendations: []
        };
        
        // Check IP reputation
        const ipStats = await IPLog.getIPStats(ip, 24); // Last 24 hours
        
        // Factor 1: Multiple accounts from same IP
        const uniqueUsers = new Set();
        ipStats.forEach(stat => {
            if (stat.uniqueUsers) {
                stat.uniqueUsers.forEach(userId => {
                    if (userId) uniqueUsers.add(userId.toString());
                });
            }
        });
        
        if (uniqueUsers.size > 3) {
            analysis.riskScore += 40;
            analysis.riskFactors.push('multiple_accounts');
            analysis.recommendations.push('Consider IP blocking');
        }
        
        // Factor 2: High request frequency
        const totalRequests = ipStats.reduce((sum, stat) => sum + (stat.count || 0), 0);
        if (totalRequests > 500) {
            analysis.riskScore += 30;
            analysis.riskFactors.push('high_frequency');
        }
        
        // Factor 3: VPN/Proxy detection
        if (ipInfo.vpn || ipInfo.proxy) {
            analysis.riskScore += 25;
            analysis.riskFactors.push('vpn_proxy');
        }
        
        // Factor 4: Geographic anomalies
        if (ipInfo.country) {
            // Check for unusual country for service (customize based on target market)
            const unusualCountries = ['RU', 'CN', 'UA', 'TR', 'VN'];
            if (unusualCountries.includes(ipInfo.countryCode)) {
                analysis.riskScore += 15;
                analysis.riskFactors.push('unusual_location');
            }
        }
        
        // Factor 5: Recent blocks
        const recentBlocks = await IPLog.countDocuments({
            ipAddress: ip,
            action: 'blocked_attempt',
            timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        });
        
        if (recentBlocks > 0) {
            analysis.riskScore += 20 * Math.min(recentBlocks, 5);
            analysis.riskFactors.push('previous_blocks');
        }
        
        analysis.riskScore = Math.min(analysis.riskScore, 100);
        analysis.level = this.getRiskLevel(analysis.riskScore);
        
        return analysis;
    }
    
    async checkMultipleAccounts(data) {
        const { ip, email, deviceFingerprint } = data;
        
        const result = { score: 0 };
        
        // Check IP-based multiple accounts
        const ipUsers = await IPLog.distinct('userId', {
            ipAddress: ip,
            action: 'signup',
            timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        });
        
        const ipUserCount = ipUsers.length;
        
        if (ipUserCount >= 3) {
            result.score = 40;
            result.flag = 'multiple_accounts';
            result.details = { ipUserCount };
        } else if (ipUserCount >= 2) {
            result.score = 20;
            result.flag = 'multiple_accounts';
            result.details = { ipUserCount };
        }
        
        // Check device fingerprint across users
        if (deviceFingerprint) {
            const deviceUsers = await User.countDocuments({
                'deviceHistory.fingerprint': deviceFingerprint,
                createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
            });
            
            if (deviceUsers > 1) {
                result.score += 30;
                result.flag = 'device_sharing';
                result.details.deviceUserCount = deviceUsers;
            }
        }
        
        // Check email pattern
        if (email) {
            const emailDomain = email.split('@')[1];
            const similarEmails = await User.countDocuments({
                email: { $regex: `@${emailDomain}$`, $options: 'i' },
                createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
            });
            
            if (similarEmails > 5) {
                result.score += 25;
                if (!result.flag) result.flag = 'email_pattern';
                result.details.similarEmailCount = similarEmails;
            }
        }
        
        return result;
    }
    
    async checkRapidActivity(data) {
        const { ip } = data;
        
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        
        const recentSignups = await IPLog.countDocuments({
            ipAddress: ip,
            action: 'signup',
            timestamp: { $gte: oneHourAgo }
        });
        
        if (recentSignups > 2) {
            return {
                score: Math.min(35, recentSignups * 15),
                flag: 'rapid_activity',
                details: { recentSignups }
            };
        }
        
        return { score: 0 };
    }
    
    checkSuspiciousEmail(data) {
        const { email } = data;
        
        if (!email) return { score: 0 };
        
        const emailDomain = email.split('@')[1]?.toLowerCase();
        const username = email.split('@')[0];
        
        let score = 0;
        let flag = null;
        const details = {};
        
        // Check for disposable emails
        if (this.disposableEmailDomains.includes(emailDomain)) {
            score = 50;
            flag = 'disposable_email';
            details.disposableDomain = true;
        }
        
        // Check for random/patterned usernames
        const randomPattern = /^[a-z0-9]{10,}$/i;
        const sequentialPattern = /(12345|67890|abcde|qwerty)/i;
        
        if (randomPattern.test(username) && username.length > 15) {
            score += 20;
            flag = flag || 'random_email';
            details.randomUsername = true;
        }
        
        if (sequentialPattern.test(username)) {
            score += 15;
            flag = flag || 'patterned_email';
            details.sequentialPattern = true;
        }
        
        // Check for email providers known for abuse
        const highRiskDomains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com'];
        if (highRiskDomains.includes(emailDomain)) {
            // These are common but legitimate, so lower score
            score += 5;
        }
        
        return { score, flag, details };
    }
    
    checkUnusualTiming(data) {
        const now = new Date();
        const hour = now.getUTCHours();
        const day = now.getUTCDay(); // 0 = Sunday, 6 = Saturday
        
        let score = 0;
        let flag = null;
        const details = { hour, day };
        
        // Unusual hours (midnight to 5 AM UTC)
        if (hour >= 0 && hour <= 5) {
            score = 15;
            flag = 'unusual_timing';
            details.unusualHour = true;
        }
        
        // Weekend activity might be more suspicious for certain patterns
        if (day === 0 || day === 6) { // Weekend
            score += 5;
            details.weekend = true;
        }
        
        return { score, flag, details };
    }
    
    async checkDeviceFingerprint(data) {
        const { deviceFingerprint, userAgent } = data;
        
        if (!deviceFingerprint) return { score: 0 };
        
        let score = 0;
        let flag = null;
        const details = {};
        
        // Check for headless browser indicators
        if (userAgent) {
            const ua = userAgent.toLowerCase();
            const headlessIndicators = [
                'headless', 'phantom', 'selenium', 'puppeteer',
                'webdriver', 'chrome-lighthouse'
            ];
            
            for (const indicator of headlessIndicators) {
                if (ua.includes(indicator)) {
                    score = 60;
                    flag = 'headless_browser';
                    details.headlessDetected = true;
                    break;
                }
            }
            
            // Check for missing or minimal user agent
            if (userAgent.length < 20) {
                score += 20;
                flag = flag || 'minimal_user_agent';
                details.minimalUA = true;
            }
        }
        
        // Check device fingerprint uniqueness
        const deviceCount = await User.countDocuments({
            'deviceHistory.fingerprint': deviceFingerprint
        });
        
        if (deviceCount > 3) {
            score += 30;
            flag = flag || 'shared_device';
            details.deviceCount = deviceCount;
        }
        
        return { score, flag, details };
    }
    
    async checkBehaviorPatterns(data) {
        const { ip, userAgent, deviceFingerprint } = data;
        
        // Look for behavioral patterns across the system
        const patterns = await this.detectBehavioralPatterns(ip, userAgent, deviceFingerprint);
        
        if (patterns.length > 0) {
            return {
                score: patterns.length * 20,
                flag: 'behavior_pattern',
                details: { patterns }
            };
        }
        
        return { score: 0 };
    }
    
    async checkReferralAbuse(data) {
        // This would check for referral farming patterns
        // Implement based on your referral system
        
        return { score: 0 };
    }
    
    async checkTaskCompletionPatterns(data) {
        // This would check for abnormal task completion patterns
        // Implement based on your task system
        
        return { score: 0 };
    }
    
    async detectBehavioralPatterns(ip, userAgent, deviceFingerprint) {
        const patterns = [];
        
        // Pattern 1: Same IP, different user agents in short time
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        const userAgents = await IPLog.distinct('userAgent', {
            ipAddress: ip,
            timestamp: { $gte: oneHourAgo }
        });
        
        if (userAgents.length > 3) {
            patterns.push('multiple_user_agents');
        }
        
        // Pattern 2: Rapid sequence of different actions
        const actions = await IPLog.find({
            ipAddress: ip,
            timestamp: { $gte: new Date(Date.now() - 5 * 60 * 1000) }
        }).sort({ timestamp: 1 }).limit(20);
        
        if (actions.length > 10) {
            let changes = 0;
            for (let i = 1; i < actions.length; i++) {
                if (actions[i].action !== actions[i-1].action) {
                    changes++;
                }
            }
            
            if (changes > 5) {
                patterns.push('rapid_action_changes');
            }
        }
        
        return patterns;
    }
    
    getRiskLevel(score) {
        if (score >= securityConfig.FRAUD_DETECTION.THRESHOLDS.HIGH_RISK) {
            return 'high';
        } else if (score >= securityConfig.FRAUD_DETECTION.THRESHOLDS.MEDIUM_RISK) {
            return 'medium';
        } else if (score >= securityConfig.FRAUD_DETECTION.THRESHOLDS.LOW_RISK) {
            return 'low';
        }
        return 'normal';
    }
    
    async monitorUserActivity(userId, action, data) {
        try {
            const user = await User.findById(userId);
            if (!user) return;
            
            let riskIncrease = 0;
            const newFlags = [];
            
            switch (action) {
                case 'rapid_task_completion':
                    // Check if user completed tasks too quickly
                    const lastHour = new Date(Date.now() - 60 * 60 * 1000);
                    const recentTasks = user.completedTasks.filter(
                        task => task.completedAt > lastHour
                    ).length;
                    
                    if (recentTasks > 10) {
                        riskIncrease = 25;
                        newFlags.push('rapid_task_completion');
                    }
                    break;
                    
                case 'unusual_ip_change':
                    // User accessed from a new IP that's far from previous IPs
                    riskIncrease = 30;
                    newFlags.push('unusual_ip_change');
                    break;
                    
                case 'suspicious_wallet_connection':
                    // Multiple wallet connections or suspicious wallet patterns
                    riskIncrease = 40;
                    newFlags.push('suspicious_wallet');
                    break;
                    
                case 'referral_abuse':
                    // Unusual referral patterns
                    riskIncrease = 35;
                    newFlags.push('referral_abuse');
                    break;
            }
            
            if (riskIncrease > 0) {
                user.riskScore = Math.min(user.riskScore + riskIncrease, 100);
                
                // Add new flags
                newFlags.forEach(flag => {
                    if (!user.flags.includes(flag)) {
                        user.flags.push(flag);
                    }
                });
                
                // Update suspicious status
                if (user.riskScore > securityConfig.FRAUD_DETECTION.AUTO_ACTION.FLAG_AT) {
                    user.isFlagged = true;
                }
                
                if (user.riskScore > securityConfig.FRAUD_DETECTION.AUTO_ACTION.RESTRICT_AT) {
                    user.isSuspicious = true;
                    user.restrictions.push('manual_review');
                }
                
                await user.save();
                
                // Log the suspicious activity
                await SecurityLog.create({
                    userId,
                    type: 'suspicious_activity',
                    action,
                    severity: riskIncrease > 30 ? 'high' : 'medium',
                    details: data,
                    riskScore: user.riskScore
                });
                
                logger.warn(`User ${userId} flagged for ${action}, risk score: ${user.riskScore}`);
            }
            
        } catch (error) {
            logger.error('User activity monitoring error:', error);
        }
    }
    
    async getRiskReport(userId) {
        const user = await User.findById(userId);
        if (!user) return null;
        
        const report = {
            userId,
            riskScore: user.riskScore,
            riskLevel: this.getRiskLevel(user.riskScore),
            flags: user.flags,
            restrictions: user.restrictions,
            isSuspicious: user.isSuspicious,
            isFlagged: user.isFlagged,
            ipHistory: user.ipHistory.length,
            deviceHistory: user.deviceHistory.length,
            totalPoints: user.moonPoints,
            accountAge: Date.now() - user.createdAt,
            recommendations: []
        };
        
        // Generate recommendations based on risk factors
        if (user.riskScore > 70) {
            report.recommendations.push('Require additional verification');
            report.recommendations.push('Limit task completion rate');
        }
        
        if (user.flags.includes('multiple_accounts')) {
            report.recommendations.push('Review IP associations');
        }
        
        if (user.flags.includes('rapid_activity')) {
            report.recommendations.push('Implement rate limiting');
        }
        
        return report;
    }
    
    async cleanupOldData(days = 30) {
        const cutoffDate = new Date(Date.now() - days * 24 * 60 *
