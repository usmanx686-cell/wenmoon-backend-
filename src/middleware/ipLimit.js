const IPLog = require('../models/IPLog');
const BlockedIP = require('../models/BlockedIP');
const Whitelist = require('../models/Whitelist');
const User = require('../models/User');
const logger = require('../utils/logger');
const securityConfig = require('../config/security');
const { getIPInfo } = require('../services/ipService');
const fraudDetection = require('../services/fraudDetection');

/**
 * Get client IP address from request
 */
const getClientIP = (req) => {
    // Check for forwarded IP headers (behind proxy)
    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor) {
        // Get the first IP in the list (client IP)
        const ips = forwardedFor.split(',');
        return ips[0].trim();
    }
    
    // Check for other common headers
    const realIP = req.headers['x-real-ip'];
    if (realIP) return realIP;
    
    // Fallback to connection remote address
    return req.ip || req.connection.remoteAddress;
};

/**
 * Check if IP is in blocked range
 */
const isIPBlockedRange = (ip) => {
    const blockedRanges = securityConfig.IP_LIMITING.BLOCKED_RANGES;
    
    for (const range of blockedRanges) {
        if (ipInRange(ip, range)) {
            return true;
        }
    }
    
    return false;
};

/**
 * Helper function to check if IP is in CIDR range
 */
function ipInRange(ip, range) {
    const [rangeIP, prefix] = range.split('/');
    if (!prefix) return ip === rangeIP;
    
    const mask = ~((1 << (32 - parseInt(prefix))) - 1);
    const ipNum = ipToNumber(ip);
    const rangeIPNum = ipToNumber(rangeIP);
    
    return (ipNum & mask) === (rangeIPNum & mask);
}

function ipToNumber(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

/**
 * Main IP limiting middleware
 * Enforces maximum 5 users per IP
 */
const checkIPLimit = async (req, res, next) => {
    try {
        const ip = getClientIP(req);
        
        if (!securityConfig.IP_LIMITING.ENABLED) {
            req.clientIP = ip;
            return next();
        }

        // Check if IP is whitelisted
        const isWhitelisted = await Whitelist.isWhitelisted(ip);
        if (isWhitelisted) {
            logger.debug(`Whitelisted IP: ${ip}`);
            req.clientIP = ip;
            req.ipWhitelisted = true;
            return next();
        }

        // Check if IP is in blocked ranges
        if (isIPBlockedRange(ip)) {
            logger.warn(`Blocked IP range attempt: ${ip}`);
            
            await IPLog.create({
                ipAddress: ip,
                action: 'blocked_attempt',
                userAgent: req.useragent?.source,
                endpoint: req.originalUrl,
                method: req.method,
                riskScore: 100,
                riskFactors: ['blocked_range'],
                isBlocked: true,
                blockReason: 'Blocked IP range',
                blockType: 'permanent'
            });
            
            return res.status(403).json({
                status: 'error',
                message: 'Access from this network is not allowed',
                code: 'IP_BLOCKED_RANGE'
            });
        }

        // Check if IP is blocked in database
        const isBlocked = await BlockedIP.isBlocked(ip);
        if (isBlocked) {
            logger.warn(`Blocked IP attempt: ${ip} - ${isBlocked.reason}`);
            
            await IPLog.create({
                ipAddress: ip,
                action: 'blocked_attempt',
                userAgent: req.useragent?.source,
                endpoint: req.originalUrl,
                method: req.method,
                riskScore: 100,
                riskFactors: ['already_blocked'],
                isBlocked: true,
                blockReason: isBlocked.reason,
                blockType: isBlocked.blockType
            });
            
            return res.status(403).json({
                status: 'error',
                message: 'Access from this IP is temporarily blocked',
                reason: isBlocked.reason,
                expires: isBlocked.blockExpires,
                code: 'IP_BLOCKED'
            });
        }

        // Get IP information
        const ipInfo = await getIPInfo(ip);
        req.ipInfo = ipInfo;
        
        // Check for VPN/Proxy
        if (securityConfig.IP_LIMITING.CHECK_VPN_PROXY && (ipInfo.vpn || ipInfo.proxy)) {
            req.isVPN = true;
            req.riskScore = (req.riskScore || 0) + 30;
            
            await IPLog.create({
                ipAddress: ip,
                action: 'suspicious_activity',
                userAgent: req.useragent?.source,
                endpoint: req.originalUrl,
                method: req.method,
                country: ipInfo.country,
                city: ipInfo.city,
                isp: ipInfo.isp,
                vpn: ipInfo.vpn,
                proxy: ipInfo.proxy,
                riskScore: 30,
                riskFactors: ['vpn_proxy']
            });
        }

        // Check IP limit for signups
        if (req.originalUrl.includes('/signup')) {
            const ipLimit = await IPLog.checkIPLimit(ip, securityConfig.IP_LIMITING.MAX_USERS_PER_IP);
            
            if (!ipLimit.allowed) {
                // Auto-block IP if exceeds limit significantly
                if (ipLimit.currentCount >= securityConfig.IP_LIMITING.MAX_USERS_PER_IP * 2) {
                    await BlockedIP.blockIP(ip, 
                        `Exceeded maximum users per IP (${ipLimit.currentCount}/${securityConfig.IP_LIMITING.MAX_USERS_PER_IP})`,
                        securityConfig.IP_LIMITING.BAN_DURATION
                    );
                }
                
                await IPLog.create({
                    ipAddress: ip,
                    action: 'blocked_attempt',
                    userAgent: req.useragent?.source,
                    endpoint: req.originalUrl,
                    method: req.method,
                    riskScore: 100,
                    riskFactors: ['multiple_accounts'],
                    isBlocked: true,
                    blockReason: `Exceeded maximum users per IP (${ipLimit.currentCount}/${securityConfig.IP_LIMITING.MAX_USERS_PER_IP})`
                });
                
                logger.warn(`IP limit exceeded: ${ip} has ${ipLimit.currentCount} users`);
                
                return res.status(429).json({
                    status: 'error',
                    message: `Maximum account limit reached for this network. Only ${securityConfig.IP_LIMITING.MAX_USERS_PER_IP} accounts allowed per IP.`,
                    currentCount: ipLimit.currentCount,
                    maxAllowed: securityConfig.IP_LIMITING.MAX_USERS_PER_IP,
                    code: 'IP_LIMIT_EXCEEDED'
                });
            }
            
            // Check for suspicious activity patterns
            const ipStats = await IPLog.getIPStats(ip, 1); // Last hour
            const recentSignups = ipStats.find(stat => stat.action === 'signup')?.count || 0;
            
            if (recentSignups > 2) {
                req.ipRiskScore = Math.min(100, recentSignups * 30);
                req.ipFlagged = true;
                
                // Run fraud detection
                const fraudResult = await fraudDetection.analyzeIP(ip, ipInfo);
                if (fraudResult.riskScore > 70) {
                    return res.status(429).json({
                        status: 'error',
                        message: 'Suspicious activity detected from this network',
                        code: 'SUSPICIOUS_ACTIVITY'
                    });
                }
            }
            
            req.ipStats = ipLimit;
        }

        // Store IP info in request
        req.clientIP = ip;
        req.ipInfo = ipInfo;
        
        // Log IP activity for this request
        req.ipLogAction = 'api_request';
        
        next();
    } catch (error) {
        logger.error('IP limit check error:', error);
        
        // Fail open in case of error (allow request)
        // But log the error for investigation
        req.clientIP = getClientIP(req);
        next();
    }
};

/**
 * IP validation middleware for all requests
 */
const validateIP = async (req, res, next) => {
    try {
        const ip = getClientIP(req);
        
        // Quick check for blocked ranges
        if (isIPBlockedRange(ip)) {
            return res.status(403).json({
                status: 'error',
                message: 'Access from this network is not allowed',
                code: 'IP_BLOCKED_RANGE'
            });
        }
        
        // Check database for blocked IPs (cached)
        const isBlocked = await BlockedIP.isBlocked(ip);
        if (isBlocked) {
            return res.status(403).json({
                status: 'error',
                message: 'Access from this IP is temporarily blocked',
                reason: isBlocked.reason,
                code: 'IP_BLOCKED'
            });
        }
        
        req.clientIP = ip;
        next();
    } catch (error) {
        logger.error('IP validation error:', error);
        // Continue with request even if validation fails
        req.clientIP = getClientIP(req);
        next();
    }
};

/**
 * Admin IP whitelist middleware
 */
const checkAdminIP = async (req, res, next) => {
    const ip = getClientIP(req);
    
    const isAdminIP = await Whitelist.isAdminIP(ip);
    if (!isAdminIP) {
        logger.warn(`Unauthorized admin access attempt from IP: ${ip}`);
        return res.status(403).json({
            status: 'error',
            message: 'Admin access denied',
            code: 'ADMIN_ACCESS_DENIED'
        });
    }
    
    next();
};

/**
 * Log IP activity middleware
 */
const logIPActivity = async (req, res, next) => {
    const startTime = Date.now();
    
    // Store original end method
    const originalEnd = res.end;
    
    res.end = function(chunk, encoding) {
        // Restore original end method
        res.end = originalEnd;
        
        // Calculate response time
        const responseTime = Date.now() - startTime;
        
        // Log asynchronously (don't block response)
        setImmediate(async () => {
            try {
                const ip = req.clientIP;
                const action = req.ipLogAction || 'api_request';
                
                // Skip logging for health checks and static files
                if (req.originalUrl === '/health' || 
                    req.originalUrl.includes('.')) {
                    return;
                }
                
                // Get IP info if not already present
                const ipInfo = req.ipInfo || await getIPInfo(ip);
                
                await IPLog.create({
                    ipAddress: ip,
                    userId: req.user?._id,
                    sessionId: req.sessionID,
                    action: action,
                    endpoint: req.originalUrl,
                    method: req.method,
                    userAgent: req.useragent?.source,
                    referrer: req.headers.referer,
                    
                    // Geolocation
                    country: ipInfo.country,
                    countryCode: ipInfo.countryCode,
                    region: ipInfo.region,
                    regionName: ipInfo.regionName,
                    city: ipInfo.city,
                    zip: ipInfo.zip,
                    lat: ipInfo.lat,
                    lon: ipInfo.lon,
                    timezone: ipInfo.timezone,
                    isp: ipInfo.isp,
                    org: ipInfo.org,
                    as: ipInfo.as,
                    
                    // Security flags
                    vpn: ipInfo.vpn || false,
                    proxy: ipInfo.proxy || false,
                    hosting: ipInfo.hosting || false,
                    tor: ipInfo.tor || false,
                    
                    // Risk assessment
                    riskScore: req.riskScore || 0,
                    riskFactors: req.riskFactors || [],
                    
                    // Response info
                    statusCode: res.statusCode,
                    responseTime: responseTime,
                    responseSize: res.get('Content-Length') || 0,
                    
                    // Metadata
                    headers: {
                        'user-agent': req.headers['user-agent'],
                        'accept': req.headers['accept'],
                        'accept-language': req.headers['accept-language'],
                        'content-type': req.headers['content-type']
                    },
                    queryParams: Object.keys(req.query).length > 0 ? req.query : undefined,
                    bodyHash: req.body ? 
                        require('crypto').createHash('md5').update(JSON.stringify(req.body)).digest('hex') : 
                        undefined
                });
                
            } catch (error) {
                logger.error('Failed to log IP activity:', error);
            }
        });
        
        // Call original end method
        return originalEnd.call(this, chunk, encoding);
    };
    
    next();
};

/**
 * Rate limiting based on IP risk score
 */
const dynamicRateLimit = () => {
    return async (req, res, next) => {
        try {
            const ip = req.clientIP || getClientIP(req);
            
            // Get IP risk score
            const ipAnalysis = await IPLog.analyzeIPRisk(ip);
            req.ipRiskScore = ipAnalysis.riskScore;
            
            // Apply stricter rate limits for high-risk IPs
            if (ipAnalysis.riskScore > 70) {
                // Check if we should temporarily block
                const recentBlocks = await IPLog.countDocuments({
                    ipAddress: ip,
                    action: 'blocked_attempt',
                    timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) }
                });
                
                if (recentBlocks > 3) {
                    await BlockedIP.blockIP(ip, 
                        'Excessive suspicious activity',
                        60 * 60 * 1000 // 1 hour
                    );
                    
                    return res.status(429).json({
                        status: 'error',
                        message: 'Excessive requests from this IP',
                        code: 'RATE_LIMIT_EXCEEDED'
                    });
                }
            }
            
            next();
        } catch (error) {
            logger.error('Dynamic rate limit error:', error);
            next();
        }
    };
};

module.exports = {
    checkIPLimit,
    validateIP,
    checkAdminIP,
    logIPActivity,
    dynamicRateLimit,
    getClientIP
};
