const { validationResult, body, query, param, header } = require('express-validator');
const logger = require('../utils/logger');

/**
 * Validation middleware wrapper
 */
const validate = (validations) => {
    return async (req, res, next) => {
        // Run all validations
        await Promise.all(validations.map(validation => validation.run(req)));

        const errors = validationResult(req);
        if (errors.isEmpty()) {
            return next();
        }

        // Format errors
        const formattedErrors = errors.array().map(err => ({
            field: err.param,
            message: err.msg,
            value: err.value,
            location: err.location
        }));

        logger.debug('Validation failed:', {
            url: req.originalUrl,
            errors: formattedErrors
        });

        res.status(400).json({
            status: 'error',
            message: 'Validation failed',
            errors: formattedErrors,
            code: 'VALIDATION_FAILED'
        });
    };
};

/**
 * Common validation rules
 */
const validationRules = {
    // Auth validations
    signup: [
        body('email')
            .isEmail().withMessage('Valid email is required')
            .normalizeEmail()
            .isLength({ max: 100 }).withMessage('Email too long'),
        
        body('password')
            .isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
            .isLength({ max: 100 }).withMessage('Password too long')
            .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
            .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
            .matches(/\d/).withMessage('Password must contain at least one number'),
        
        body('name')
            .trim()
            .isLength({ min: 2 }).withMessage('Name must be at least 2 characters')
            .isLength({ max: 50 }).withMessage('Name too long')
            .matches(/^[a-zA-Z0-9\s]+$/).withMessage('Name can only contain letters, numbers, and spaces'),
        
        body('captchaToken')
            .optional()
            .isString().withMessage('Captcha token must be a string')
            .isLength({ min: 1 }).withMessage('Captcha token is required')
    ],

    login: [
        body('email')
            .isEmail().withMessage('Valid email is required')
            .normalizeEmail(),
        
        body('password')
            .isLength({ min: 1 }).withMessage('Password is required')
    ],

    socialAuth: [
        body('provider')
            .isIn(['google', 'telegram']).withMessage('Provider must be google or telegram'),
        
        body('token')
            .isString().withMessage('Token must be a string')
            .isLength({ min: 1 }).withMessage('Token is required'),
        
        body('name')
            .optional()
            .isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters'),
        
        body('email')
            .optional()
            .isEmail().withMessage('Valid email is required')
            .normalizeEmail()
    ],

    forgotPassword: [
        body('email')
            .isEmail().withMessage('Valid email is required')
            .normalizeEmail(),
        
        body('captchaToken')
            .optional()
            .isString().withMessage('Captcha token must be a string')
    ],

    resetPassword: [
        body('token')
            .isString().withMessage('Token is required')
            .isLength({ min: 1 }).withMessage('Token is required'),
        
        body('password')
            .isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
            .isLength({ max: 100 }).withMessage('Password too long')
            .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
            .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
            .matches(/\d/).withMessage('Password must contain at least one number')
    ],

    // User validations
    updateProfile: [
        body('name')
            .optional()
            .trim()
            .isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters'),
        
        body('avatar')
            .optional()
            .isURL().withMessage('Avatar must be a valid URL')
            .matches(/\.(jpg|jpeg|png|gif|webp)$/i).withMessage('Avatar must be an image URL')
    ],

    connectWallet: [
        body('walletAddress')
            .matches(/^0x[a-fA-F0-9]{40}$/).withMessage('Invalid Ethereum address'),
        
        body('signature')
            .optional()
            .isString().withMessage('Signature must be a string')
    ],

    processReferral: [
        body('referralCode')
            .isString().withMessage('Referral code is required')
            .isLength({ min: 8, max: 12 }).withMessage('Invalid referral code format')
            .matches(/^[a-zA-Z0-9]+$/).withMessage('Referral code can only contain letters and numbers')
    ],

    // Task validations
    completeTask: [
        param('id')
            .isMongoId().withMessage('Invalid task ID'),
        
        body('proof')
            .optional()
            .isString().withMessage('Proof must be a string')
            .isLength({ max: 1000 }).withMessage('Proof too long')
    ],

    // Admin validations
    blockIP: [
        body('ipAddress')
            .isIP().withMessage('Valid IP address is required'),
        
        body('reason')
            .isString().withMessage('Reason is required')
            .isLength({ min: 5, max: 500 }).withMessage('Reason must be between 5 and 500 characters'),
        
        body('duration')
            .optional()
            .isInt({ min: 0 }).withMessage('Duration must be a positive number in milliseconds'),
        
        body('blockType')
            .optional()
            .isIn(['temporary', 'permanent', 'manual', 'automatic']).withMessage('Invalid block type')
    ],

    whitelistIP: [
        body('ipAddress')
            .isIP().withMessage('Valid IP address is required'),
        
        body('reason')
            .isString().withMessage('Reason is required')
            .isLength({ min: 5, max: 200 }).withMessage('Reason must be between 5 and 200 characters'),
        
        body('type')
            .isIn(['admin', 'user', 'api']).withMessage('Type must be admin, user, or api'),
        
        body('expiresAt')
            .optional()
            .isISO8601().withMessage('Expiration date must be in ISO8601 format')
    ]
};

/**
 * Sanitize input data
 */
const sanitize = {
    email: (email) => email.toLowerCase().trim(),
    name: (name) => name.trim().replace(/\s+/g, ' '),
    string: (str) => str.trim(),
    url: (url) => url.trim()
};

/**
 * Custom validators
 */
const customValidators = {
    // Check if email domain is not disposable
    isNotDisposableEmail: (email) => {
        const disposableDomains = [
            'tempmail.com', 'mailinator.com', 'guerrillamail.com',
            '10minutemail.com', 'yopmail.com', 'trashmail.com'
        ];
        
        const domain = email.split('@')[1]?.toLowerCase();
        return !disposableDomains.includes(domain);
    },

    // Check if username is not reserved
    isNotReservedName: (name) => {
        const reservedNames = [
            'admin', 'administrator', 'moderator', 'support',
            'help', 'info', 'contact', 'system', 'root'
        ];
        
        return !reservedNames.includes(name.toLowerCase());
    },

    // Validate Ethereum address (case-insensitive checksum)
    isValidEthAddress: (address) => {
        return /^0x[a-fA-F0-9]{40}$/.test(address);
    },

    // Validate referral code format
    isValidReferralCode: (code) => {
        return /^[A-Z0-9]{8,12}$/i.test(code);
    }
};

/**
 * Validation error formatter
 */
const formatValidationErrors = (errors) => {
    return errors.array().reduce((acc, error) => {
        if (!acc[error.param]) {
            acc[error.param] = [];
        }
        acc[error.param].push(error.msg);
        return acc;
    }, {});
};

module.exports = {
    validate,
    validationRules,
    sanitize,
    customValidators,
    formatValidationErrors
};
