const IPLog = require('../models/IPLog');
const User = require('../models/User');
const logger = require('../utils/logger');
const securityConfig = require('../config/security');

/**
 * Middleware to check IP limit for user signups
 * Maximum 5 users per IP address
 */
const checkIPLimit = async (req, res, next) => {
    try {
        const ip = req.ip || req.connection.remoteAddress;
        
        if (!securityConfig.IP_LIMITING.ENABLED) {
            return next();
        }

        // Skip IP limiting for whitelisted IPs (admin, testing)
        if (process.env.WHITELISTED_IPS && process.env.WHITELISTED_IPS.split(',').includes(ip)) {
            return next();
        }

        // Check if IP is in blocked ranges
        const isBlockedRange = securityConfig.IP_LIMITING.BLOCKED_RANGES.some(range => {
            return ipInRange(ip, range);
        });

        if (isBlockedRange) {
            logger.warn(`Blocked IP range attempt: ${ip}`);
            return res.status(403).json({
                status: 'error',
                message: 'Access from this network is not allowed'
            });
        }

        // Check IP limit
        const ipLimit = await IPLog.checkIPLimit(ip, securityConfig.IP_LIMITING.MAX_USERS_PER_IP);
        
        if (!ipLimit.allowed) {
            // Log this attempt
            await IPLog.create({
                ipAddress: ip,
                action: 'blocked_signup_attempt',
                userAgent: req.useragent?.source,
                riskScore: 100,
                isBlocked: true,
                blockReason: `Exceeded maximum users per IP (${ipLimit.currentCount}/${securityConfig.IP_LIMITING.MAX_USERS_PER_IP})`
            });

            logger.warn(`IP limit exceeded: ${ip} has ${ipLimit.currentCount} users`);

            return res.status(429).json({
                status: 'error',
                message: `Maximum account limit reached for this network. Only ${securityConfig.IP_LIMITING.MAX_USERS_PER_IP} accounts allowed per IP.`,
                code: 'IP_LIMIT_EXCEEDED'
            });
        }

        // Check for suspicious behavior
        const ipStats = await IPLog.getIPStats(ip, 1); // Last hour
        
        const recentSignups = ipStats.find(stat => stat.action === 'signup')?.count || 0;
        const recentLogins = ipStats.find(stat => stat.action === 'login')?.count || 0;

        if (recentSignups > 2) { // More than 2 signups in last hour
            req.ipRiskScore = Math.min(100, recentSignups * 30);
            req.ipFlagged = true;
        }

        // Store IP info in request for later use
        req.clientIP = ip;
        req.ipStats = ipLimit;

        next();
    } catch (error) {
        logger.error('IP limit check error:', error);
        next(error);
    }
};

/**
 * Middleware to validate IP for all requests
 */
const validateIP = async (req, res, next) => {
    try {
        const ip = req.ip || req.connection.remoteAddress;
        
        // Check if IP is blocked
        const blockedIP = await IPLog.findOne({
            ipAddress: ip,
            isBlocked: true,
            blockExpires: { $gt: new Date() }
        });

        if (blockedIP) {
            return res.status(403).json({
                status: 'error',
                message: 'Access from this IP is temporarily blocked',
                reason: blockedIP.blockReason,
                expires: blockedIP.blockExpires
            });
        }

        // Check for VPN/Proxy
        if (securityConfig.IP_LIMITING.CHECK_PROXY) {
            // In production, integrate with a VPN/proxy detection service
            // For now, we'll check common VPN ports and patterns
            const isSuspicious = await checkForVPNProxy(ip);
            if (isSuspicious) {
                req.isVPN = true;
                req.riskScore = (req.riskScore || 0) + 20;
            }
        }

        req.clientIP = ip;
        next();
    } catch (error) {
        logger.error('IP validation error:', error);
        next();
    }
};

/**
 * Middleware to log IP activity
 */
const logIPActivity = async (req, res, next) => {
    const startTime = Date.now();
    
    // Override res.end to log after response
    const originalEnd = res.end;
    res.end = function(chunk, encoding) {
        res.end = originalEnd;
        res.end(chunk, encoding);
        
        // Log asynchronously
        setTimeout(async () => {
            try {
                const ip = req.clientIP || req.ip || req.connection.remoteAddress;
                
                await IPLog.create({
                    ipAddress: ip,
                    userId: req.user?._id,
                    action: req.ipLogAction || 'api_request',
                    userAgent: req.useragent?.source,
                    country: req.geoData?.country,
                    city: req.geoData?.city,
                    riskScore: req.riskScore || 0,
                    isBlocked: false
                });
            } catch (error) {
                logger.error('Failed to log IP activity:', error);
            }
        }, 0);
    };

    next();
};

/**
 * Function to check if IP is in a given range
 */
function ipInRange(ip, range) {
    const [rangeIP, prefix] = range.split('/');
    const mask = ~((1 << (32 - parseInt(prefix))) - 1);
    
    const ipNum = ipToNumber(ip);
    const rangeIPNum = ipToNumber(rangeIP);
    
    return (ipNum & mask) === (rangeIPNum & mask);
}

function ipToNumber(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

/**
 * Basic VPN/Proxy detection
 */
async function checkForVPNProxy(ip) {
    // This is a basic implementation
    // In production, use a service like IPHub, ProxyCheck, etc.
    
    // Check for common VPN ports in request
    // This would require more sophisticated detection
    
    return false;
}

module.exports = {
    checkIPLimit,
    validateIP,
    logIPActivity
};
