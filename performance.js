const compression = require('compression');
const NodeCache = require('node-cache');
const winston = require('winston');

// Cache în memorie pentru date frecvente
const cache = new NodeCache({
    stdTTL: 300, // 5 minute default
    checkperiod: 120, // Verifică expirarea la 2 minute
    useClones: false // Performanță mai bună
});

// Logger pentru performance monitoring
const performanceLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

// Middleware pentru compression
const compressionMiddleware = compression({
    level: 6, // Nivel optim între compresie și CPU
    threshold: 1024, // Compresează doar fișiere > 1KB
    filter: (req, res) => {
        // Nu compresează dacă clientul nu suportă
        if (req.headers['x-no-compression']) return false;
        // Nu compresează fișiere deja compresate
        if (req.url.includes('.gz') || req.url.includes('.br')) return false;
        return compression.filter(req, res);
    }
});

// Middleware pentru cache headers
const cacheHeaders = (req, res, next) => {
    // Cache pentru fișiere statice
    if (req.url.match(/\.(css|js|png|jpg|jpeg|gif|ico|svg)$/)) {
        res.setHeader('Cache-Control', 'public, max-age=86400'); // 1 zi
        res.setHeader('ETag', `"${Date.now()}"`);
    }
    // Cache pentru API responses
    else if (req.url.startsWith('/api/')) {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
    }
    next();
};

// Middleware pentru performance monitoring
const performanceMonitoring = (req, res, next) => {
    const startTime = Date.now();
    const startMemory = process.memoryUsage();
    
    res.on('finish', () => {
        const endTime = Date.now();
        const endMemory = process.memoryUsage();
        const duration = endTime - startTime;
        const memoryDelta = endMemory.heapUsed - startMemory.heapUsed;
        
        // Log performance metrics
        performanceLogger.info('Request Performance', {
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            duration: `${duration}ms`,
            memoryDelta: `${Math.round(memoryDelta / 1024)}KB`,
            userAgent: req.get('User-Agent'),
            ip: req.ip
        });
        
        // Alert pentru request-uri lente
        if (duration > 5000) {
            performanceLogger.warn('Slow Request Detected', {
                url: req.url,
                duration: `${duration}ms`,
                memoryUsage: `${Math.round(endMemory.heapUsed / 1024 / 1024)}MB`
            });
        }
    });
    
    next();
};

// Funcții pentru cache management
const cacheUtils = {
    // Set cache cu TTL personalizat
    set: (key, value, ttl = 300) => {
        return cache.set(key, value, ttl);
    },
    
    // Get cache
    get: (key) => {
        return cache.get(key);
    },
    
    // Delete cache
    del: (key) => {
        return cache.del(key);
    },
    
    // Clear all cache
    flush: () => {
        return cache.flushAll();
    },
    
    // Get cache stats
    getStats: () => {
        return cache.getStats();
    },
    
    // Cache pentru utilizatori online
    cacheOnlineUsers: (users) => {
        cache.set('online_users', users, 60); // 1 minut
    },
    
    // Cache pentru statistici
    cacheStats: (stats) => {
        cache.set('dashboard_stats', stats, 300); // 5 minute
    },
    
    // Cache pentru activitate recentă
    cacheActivity: (activity) => {
        cache.set('recent_activity', activity, 180); // 3 minute
    }
};

// Cleanup pentru cache și memory management
const cleanup = () => {
    // Cleanup cache expirat
    cache.flushAll();
    
    // Force garbage collection dacă este disponibil
    if (global.gc) {
        global.gc();
        performanceLogger.info('Garbage collection triggered');
    }
    
    // Log memory usage
    const memUsage = process.memoryUsage();
    performanceLogger.info('Memory Usage', {
        rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`,
        heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
        external: `${Math.round(memUsage.external / 1024 / 1024)}MB`
    });
};

// Cleanup automat la fiecare 5 minute
setInterval(cleanup, 300000);

// Cleanup la startup
cleanup();

module.exports = {
    compressionMiddleware,
    cacheHeaders,
    performanceMonitoring,
    cacheUtils,
    performanceLogger,
    cleanup
};
