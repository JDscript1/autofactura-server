const winston = require('winston');

// Logger pentru database operations
const dbLogger = winston.createLogger({
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

// Optimizări pentru query-uri frecvente
const queryOptimizations = {
    // Optimizare pentru utilizatori online
    getOnlineUsers: (users) => {
        const startTime = Date.now();
        
        // Filtrează doar utilizatorii online
        const onlineUsers = users.filter(user => user.isOnline === true);
        
        const duration = Date.now() - startTime;
        dbLogger.info('Query Optimization - Online Users', {
            totalUsers: users.length,
            onlineUsers: onlineUsers.length,
            duration: `${duration}ms`
        });
        
        return onlineUsers;
    },
    
    // Optimizare pentru activitate recentă
    getRecentActivity: (activity, limit = 10) => {
        const startTime = Date.now();
        
        // Sortează după timestamp și limitează
        const recentActivity = activity
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, limit);
        
        const duration = Date.now() - startTime;
        dbLogger.info('Query Optimization - Recent Activity', {
            totalActivity: activity.length,
            returnedActivity: recentActivity.length,
            duration: `${duration}ms`
        });
        
        return recentActivity;
    },
    
    // Optimizare pentru statistici dashboard
    getDashboardStats: (users, invoices, clients) => {
        const startTime = Date.now();
        
        // Calculează statistici în paralel
        const stats = {
            totalUsers: users.length,
            onlineUsers: users.filter(u => u.isOnline).length,
            totalInvoices: invoices.length,
            totalClients: clients.length,
            totalRevenue: invoices.reduce((sum, inv) => sum + (inv.totalAmount || 0), 0),
            averageInvoiceValue: invoices.length > 0 ? 
                invoices.reduce((sum, inv) => sum + (inv.totalAmount || 0), 0) / invoices.length : 0
        };
        
        const duration = Date.now() - startTime;
        dbLogger.info('Query Optimization - Dashboard Stats', {
            duration: `${duration}ms`,
            statsGenerated: Object.keys(stats).length
        });
        
        return stats;
    },
    
    // Optimizare pentru căutare utilizatori
    searchUsers: (users, query) => {
        const startTime = Date.now();
        
        if (!query || query.trim() === '') {
            return users;
        }
        
        const searchTerm = query.toLowerCase();
        const filteredUsers = users.filter(user => 
            user.email?.toLowerCase().includes(searchTerm) ||
            user.firstName?.toLowerCase().includes(searchTerm) ||
            user.lastName?.toLowerCase().includes(searchTerm) ||
            user.companyName?.toLowerCase().includes(searchTerm)
        );
        
        const duration = Date.now() - startTime;
        dbLogger.info('Query Optimization - User Search', {
            query: searchTerm,
            totalUsers: users.length,
            filteredUsers: filteredUsers.length,
            duration: `${duration}ms`
        });
        
        return filteredUsers;
    },
    
    // Optimizare pentru facturi utilizator
    getUserInvoices: (invoices, userId) => {
        const startTime = Date.now();
        
        const userInvoices = invoices.filter(invoice => invoice.userId === userId);
        
        const duration = Date.now() - startTime;
        dbLogger.info('Query Optimization - User Invoices', {
            userId: userId,
            totalInvoices: invoices.length,
            userInvoices: userInvoices.length,
            duration: `${duration}ms`
        });
        
        return userInvoices;
    }
};

// Indexuri virtuale pentru performanță
const virtualIndexes = {
    // Index pentru utilizatori online
    onlineUsersIndex: new Map(),
    
    // Index pentru activitate recentă
    recentActivityIndex: new Map(),
    
    // Index pentru facturi utilizator
    userInvoicesIndex: new Map(),
    
    // Actualizează indexurile
    updateIndexes: (users, activity, invoices) => {
        const startTime = Date.now();
        
        // Index utilizatori online
        this.onlineUsersIndex.clear();
        users.forEach(user => {
            if (user.isOnline) {
                this.onlineUsersIndex.set(user.id, user);
            }
        });
        
        // Index activitate recentă
        this.recentActivityIndex.clear();
        activity
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, 50) // Păstrează doar ultimele 50
            .forEach(item => {
                this.recentActivityIndex.set(item.id, item);
            });
        
        // Index facturi utilizator
        this.userInvoicesIndex.clear();
        invoices.forEach(invoice => {
            if (!this.userInvoicesIndex.has(invoice.userId)) {
                this.userInvoicesIndex.set(invoice.userId, []);
            }
            this.userInvoicesIndex.get(invoice.userId).push(invoice);
        });
        
        const duration = Date.now() - startTime;
        dbLogger.info('Virtual Indexes Updated', {
            onlineUsers: this.onlineUsersIndex.size,
            recentActivity: this.recentActivityIndex.size,
            userInvoices: this.userInvoicesIndex.size,
            duration: `${duration}ms`
        });
    },
    
    // Obține utilizatori online din index
    getOnlineUsersFromIndex: () => {
        return Array.from(this.onlineUsersIndex.values());
    },
    
    // Obține activitate recentă din index
    getRecentActivityFromIndex: (limit = 10) => {
        return Array.from(this.recentActivityIndex.values()).slice(0, limit);
    },
    
    // Obține facturi utilizator din index
    getUserInvoicesFromIndex: (userId) => {
        return this.userInvoicesIndex.get(userId) || [];
    }
};

// Connection pooling optimization
const connectionOptimization = {
    // Configurare optimizată pentru conexiuni
    getOptimalConfig: () => {
        return {
            max: 20,        // Maximum connections
            min: 5,         // Minimum connections
            acquire: 30000, // Time to acquire connection
            idle: 10000,    // Idle time before release
            evict: 1000,    // Check for idle connections
            handleDisconnects: true
        };
    },
    
    // Monitorizare conexiuni
    monitorConnections: (sequelize) => {
        setInterval(() => {
            const pool = sequelize.connectionManager.pool;
            dbLogger.info('Connection Pool Status', {
                total: pool.size,
                used: pool.used,
                waiting: pool.pending,
                available: pool.available
            });
        }, 60000); // La fiecare minut
    }
};

// Cleanup pentru optimizări
const cleanupOptimizations = () => {
    // Curăță indexurile virtuale
    virtualIndexes.onlineUsersIndex.clear();
    virtualIndexes.recentActivityIndex.clear();
    virtualIndexes.userInvoicesIndex.clear();
    
    dbLogger.info('Database optimizations cleaned up');
};

module.exports = {
    queryOptimizations,
    virtualIndexes,
    connectionOptimization,
    cleanupOptimizations,
    dbLogger
};
