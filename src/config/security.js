module.exports = {
    // Anti-bot configuration
    BOT_DETECTION: {
        ENABLED: true,
        // Known bot user agents
        BOT_USER_AGENTS: [
            'Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot', 'Baiduspider',
            'YandexBot', 'Sogou', 'Exabot', 'facebot', 'ia_archiver',
            'AhrefsBot', 'MJ12bot', 'SeznamBot', 'dotbot', 'SemrushBot'
        ],
        // Suspicious patterns
        SUSPICIOUS_PATTERNS: [
            'bot', 'crawler', 'spider', 'scraper', 'scan', 'checker',
            'headless', 'phantom', 'selenium', 'puppeteer', 'automation'
        ],
        // Rate limits per endpoint
        RATE_LIMITS: {
            SIGNUP: 3, // 3 signups per hour per IP
            TASK_COMPLETION: 10, // 10 tasks per minute
            WALLET_CONNECTION: 2 // 2 connections per hour
        }
    },

    // IP limiting configuration
    IP_LIMITING: {
        ENABLED: true,
        MAX_USERS_PER_IP: 5,
        CHECK_PROXY: true,
        BAN_DURATION: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
        // IP ranges to block
        BLOCKED_RANGES: [
            '192.168.0.0/16',
            '10.0.0.0/8',
            '172.16.0.0/12'
        ]
    },

    // CAPTCHA configuration
    CAPTCHA: {
        ENABLED: true,
        PROVIDER: 'hcaptcha', // or 'recaptcha'
        HCAPTCHA_SECRET: process.env.HCAPTCHA_SECRET,
        RECAPTCHA_SECRET: process.env.RECAPTCHA_SECRET,
        MIN_SCORE: 0.5, // Minimum score to pass
        REQUIRED_FOR: ['signup', 'task_submission', 'wallet_connect']
    },

    // Fraud detection
    FRAUD_DETECTION: {
        ENABLED: true,
        // Behavioral patterns
        SUSPICIOUS_BEHAVIOR: {
            MULTIPLE_ACCOUNTS: true,
            RAPID_TASK_COMPLETION: true,
            UNUSUAL_TIMING: true,
            GEO_DISCREPANCY: true
        },
        // Scoring thresholds
        THRESHOLDS: {
            HIGH_RISK: 80,
            MEDIUM_RISK: 50,
            LOW_RISK: 20
        }
    }
};
