const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');

/**
 * Configurare securitate avansată pentru AutoFactura
 */

// Rate limiting pentru protecție împotriva atacurilor DDoS
const createRateLimit = (windowMs, max, message) => {
    return rateLimit({
        windowMs: windowMs,
        max: max,
        message: {
            error: message,
            retryAfter: Math.ceil(windowMs / 1000)
        },
        standardHeaders: true,
        legacyHeaders: false,
        handler: (req, res) => {
            console.warn(`🚨 Rate limit exceeded for IP: ${req.ip} on ${req.path}`);
            res.status(429).json({
                error: message,
                retryAfter: Math.ceil(windowMs / 1000)
            });
        }
    });
};

// Rate limiting pentru login (5 încercări la 15 minute)
const loginRateLimit = createRateLimit(
    15 * 60 * 1000, // 15 minute
    5, // 5 încercări
    'Prea multe încercări de login. Încercați din nou în 15 minute.'
);

// Rate limiting pentru înregistrare (3 conturi la oră)
const registerRateLimit = createRateLimit(
    60 * 60 * 1000, // 1 oră
    3, // 3 încercări
    'Prea multe încercări de înregistrare. Încercați din nou în 1 oră.'
);

// Rate limiting pentru resetare parolă (3 cereri la oră)
const forgotPasswordRateLimit = createRateLimit(
    60 * 60 * 1000, // 1 oră
    3, // 3 încercări
    'Prea multe cereri de resetare parolă. Încercați din nou în 1 oră.'
);

// Rate limiting general pentru API (100 cereri la 15 minute)
const apiRateLimit = createRateLimit(
    15 * 60 * 1000, // 15 minute
    100, // 100 cereri
    'Prea multe cereri API. Încercați din nou în 15 minute.'
);

// Slow down pentru protecție împotriva brute force
const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000, // 15 minute
    delayAfter: 2, // După 2 cereri
    delayMs: 500, // Adaugă 500ms la fiecare cerere
    maxDelayMs: 20000, // Maximum 20 secunde
    skipSuccessfulRequests: true,
    skipFailedRequests: false
});

// Configurare Helmet pentru headers de securitate
const helmetConfig = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
});

// Validare pentru înregistrare
const validateRegistration = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Email invalid'),
    body('password')
        .isLength({ min: 8 })
        .withMessage('Parola trebuie să aibă cel puțin 8 caractere')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .withMessage('Parola trebuie să conțină cel puțin o literă mică, o literă mare și o cifră'),
    body('firstName')
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('Prenumele trebuie să aibă între 2 și 50 de caractere')
        .matches(/^[a-zA-ZăâîșțĂÂÎȘȚ\s]+$/)
        .withMessage('Prenumele poate conține doar litere și spații'),
    body('lastName')
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('Numele trebuie să aibă între 2 și 50 de caractere')
        .matches(/^[a-zA-ZăâîșțĂÂÎȘȚ\s]+$/)
        .withMessage('Numele poate conține doar litere și spații'),
    body('companyName')
        .optional()
        .trim()
        .isLength({ max: 100 })
        .withMessage('Numele companiei nu poate depăși 100 de caractere')
];

// Validare pentru login
const validateLogin = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Email invalid'),
    body('password')
        .notEmpty()
        .withMessage('Parola este obligatorie')
];

// Validare pentru resetare parolă
const validateForgotPassword = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Email invalid')
];

// Middleware pentru validare
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            error: 'Date invalide',
            details: errors.array()
        });
    }
    next();
};

// Generare token CSRF
const generateCSRFToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

// Verificare token CSRF
const verifyCSRFToken = (req, res, next) => {
    const token = req.headers['x-csrf-token'] || req.body.csrfToken;
    const sessionToken = req.session.csrfToken;
    
    if (!token || !sessionToken || token !== sessionToken) {
        return res.status(403).json({
            error: 'Token CSRF invalid'
        });
    }
    
    next();
};

// Sanitizare input
const sanitizeInput = (req, res, next) => {
    // Sanitizează toate string-urile din body
    if (req.body) {
        for (let key in req.body) {
            if (typeof req.body[key] === 'string') {
                req.body[key] = req.body[key]
                    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                    .replace(/javascript:/gi, '')
                    .replace(/on\w+\s*=/gi, '')
                    .trim();
            }
        }
    }
    
    // Sanitizează query parameters
    if (req.query) {
        for (let key in req.query) {
            if (typeof req.query[key] === 'string') {
                req.query[key] = req.query[key]
                    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                    .replace(/javascript:/gi, '')
                    .replace(/on\w+\s*=/gi, '')
                    .trim();
            }
        }
    }
    
    next();
};

// Logging pentru securitate
const securityLogger = (req, res, next) => {
    const startTime = Date.now();
    
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        const logData = {
            timestamp: new Date().toISOString(),
            ip: req.ip,
            method: req.method,
            url: req.url,
            userAgent: req.headers['user-agent'],
            statusCode: res.statusCode,
            duration: duration,
            contentLength: res.get('content-length')
        };
        
        // Log doar cererile suspecte sau erorile
        if (res.statusCode >= 400 || duration > 5000) {
            console.warn('🚨 Security Event:', logData);
        }
    });
    
    next();
};

// Protecție împotriva SQL Injection (pentru query-uri manuale)
const escapeSQL = (str) => {
    if (typeof str !== 'string') return str;
    return str.replace(/[\0\x08\x09\x1a\n\r"'\\\%]/g, (char) => {
        switch (char) {
            case '\0': return '\\0';
            case '\x08': return '\\b';
            case '\x09': return '\\t';
            case '\x1a': return '\\z';
            case '\n': return '\\n';
            case '\r': return '\\r';
            case '"':
            case "'":
            case '\\':
            case '%': return '\\' + char;
            default: return char;
        }
    });
};

// Verificare IP suspect
const isSuspiciousIP = (ip) => {
    // În dezvoltare, nu blocăm localhost
    if (process.env.NODE_ENV !== 'production') {
        return false;
    }
    
    // Lista de IP-uri suspecte (în producție, ar trebui să fie într-o bază de date)
    const suspiciousIPs = [
        // Adaugă IP-uri suspecte aici pentru producție
    ];
    
    return suspiciousIPs.includes(ip);
};

// Middleware pentru blocarea IP-urilor suspecte
const blockSuspiciousIPs = (req, res, next) => {
    if (isSuspiciousIP(req.ip)) {
        console.warn(`🚨 Blocked suspicious IP: ${req.ip}`);
        return res.status(403).json({
            error: 'Acces interzis'
        });
    }
    next();
};

module.exports = {
    // Rate limiting
    loginRateLimit,
    registerRateLimit,
    forgotPasswordRateLimit,
    apiRateLimit,
    speedLimiter,
    
    // Security headers
    helmetConfig,
    
    // Validation
    validateRegistration,
    validateLogin,
    validateForgotPassword,
    handleValidationErrors,
    
    // CSRF Protection
    generateCSRFToken,
    verifyCSRFToken,
    
    // Input sanitization
    sanitizeInput,
    
    // Logging
    securityLogger,
    
    // SQL Injection protection
    escapeSQL,
    
    // IP blocking
    blockSuspiciousIPs
};
