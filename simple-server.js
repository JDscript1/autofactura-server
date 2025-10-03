const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

// Import securitate avansată
const {
    loginRateLimit,
    registerRateLimit,
    forgotPasswordRateLimit,
    apiRateLimit,
    speedLimiter,
    helmetConfig,
    validateRegistration,
    validateLogin,
    validateForgotPassword,
    handleValidationErrors,
    generateCSRFToken,
    verifyCSRFToken,
    sanitizeInput,
    securityLogger,
    escapeSQL,
    blockSuspiciousIPs
} = require('./security');

// Import sistem CAPTCHA
const {
    generateCaptcha,
    verifyCaptcha,
    isCaptchaValid,
    getCaptchaStats
} = require('./captcha');

// Import optimizări de performanță
const {
    compressionMiddleware,
    cacheHeaders,
    performanceMonitoring,
    cacheUtils,
    performanceLogger,
    cleanup
} = require('./performance');

// Import optimizări de bază de date
const {
    queryOptimizations,
    virtualIndexes,
    connectionOptimization,
    cleanupOptimizations,
    dbLogger
} = require('./database-optimization');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'autofactura_secret_key_2024';

// Middleware de securitate
app.use(helmetConfig); // Headers de securitate
app.use(securityLogger); // Logging pentru securitate
app.use(blockSuspiciousIPs); // Blocare IP-uri suspecte
app.use(sanitizeInput); // Sanitizare input
app.use(speedLimiter); // Slow down pentru brute force

// Middleware de optimizare performanță
app.use(compressionMiddleware); // Compression pentru response-uri
app.use(cacheHeaders); // Cache headers pentru fișiere statice
app.use(performanceMonitoring); // Monitoring performanță

// Middleware standard
app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? ['https://yourdomain.com'] : true,
    credentials: true
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(__dirname));

// Rate limiting pentru API
app.use('/api', apiRateLimit);

// Baza de date simplă în memorie (pentru test)
let users = [
    {
        id: 1,
        email: 'test@example.com',
        password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
        firstName: 'Test',
        lastName: 'User',
        companyName: 'Test Company',
        lastLogin: null,
        isOnline: false,
        createdAt: new Date().toISOString()
    }
];

// Tracking pentru activitatea utilizatorilor
let userActivity = [
    {
        id: 1,
        type: 'user_registration',
        description: 'Utilizator nou înregistrat',
        timestamp: new Date().toISOString(),
        userEmail: 'test@example.com',
        userAgent: 'AutoFactura Android App'
    }
];

// Tracking pentru login-uri
let loginHistory = [];

// Token-uri pentru resetarea parolei
let passwordResetTokens = [];

// Baza de date pentru clienți
let clients = [];

// Baza de date pentru facturi
let invoices = [];

// Baza de date pentru produse/servicii
let products = [];

// Configurare email (pentru test, folosește Gmail)
const emailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'autofactura.app@gmail.com',
        pass: process.env.EMAIL_PASS || 'your-app-password'
    }
});

// Middleware pentru autentificare JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token de acces necesar' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token invalid' });
        }
        req.user = user;
        next();
    });
};

// 1. Înregistrare utilizator nou cu securitate avansată
app.post('/api/register', registerRateLimit, validateRegistration, handleValidationErrors, async (req, res) => {
    try {
        const {
            email, password, firstName, lastName, companyName, cui,
            registrationNumber, caenCode, legalForm, address, phone,
            website, isVatPayer, vatNumber, countryCode, iban,
            bankName, swiftCode, legalRepresentativeName,
            legalRepresentativePosition, logoPath, isAutoInvoiceEnabled,
            defaultVatRate
        } = req.body;

        // Verifică dacă email-ul există deja
        const existingUser = users.find(u => u.email === email);
        if (existingUser) {
            return res.status(400).json({ error: 'Email-ul există deja' });
        }

        // Hash parola
        const hashedPassword = await bcrypt.hash(password, 10);

        // Creează utilizatorul nou
        const newUser = {
            id: users.length + 1,
            email,
            password: hashedPassword,
            firstName,
            lastName,
            companyName,
            cui,
            registrationNumber,
            caenCode,
            legalForm,
            address,
            phone,
            website,
            isVatPayer,
            vatNumber,
            countryCode,
            iban,
            bankName,
            swiftCode,
            legalRepresentativeName,
            legalRepresentativePosition,
            logoPath,
            isAutoInvoiceEnabled,
            defaultVatRate,
            lastLogin: null,
            isOnline: false,
            createdAt: new Date().toISOString()
        };

        users.push(newUser);

        // Adaugă activitate pentru înregistrare
        const activity = {
            id: userActivity.length + 1,
            type: 'user_registration',
            description: 'Utilizator nou înregistrat',
            timestamp: new Date().toISOString(),
            userEmail: email,
            userAgent: req.headers['user-agent'] || 'AutoFactura Android App'
        };
        userActivity.push(activity);

        // Generează token JWT
        const token = jwt.sign(
            { userId: newUser.id, email: newUser.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'Utilizator creat cu succes',
            token: token,
            user: {
                id: newUser.id,
                email: newUser.email,
                firstName: newUser.firstName,
                lastName: newUser.lastName,
                companyName: newUser.companyName
            }
        });
    } catch (error) {
        console.error('Eroare la înregistrare:', error);
        res.status(500).json({ error: 'Eroare la înregistrare' });
    }
});

// 2. Autentificare utilizator cu securitate avansată
app.post('/api/login', loginRateLimit, validateLogin, handleValidationErrors, async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = users.find(u => u.email === email);
        if (!user) {
            return res.status(401).json({ error: 'Email sau parolă incorectă' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Email sau parolă incorectă' });
        }

        // Actualizează statusul utilizatorului
        user.lastLogin = new Date().toISOString();
        user.isOnline = true;

        // Adaugă activitate pentru login
        const activity = {
            id: userActivity.length + 1,
            type: 'user_login',
            description: 'Utilizator autentificat',
            timestamp: new Date().toISOString(),
            userEmail: email,
            userAgent: req.headers['user-agent'] || 'AutoFactura Android App'
        };
        userActivity.push(activity);

        // Adaugă în istoricul de login
        const loginRecord = {
            id: loginHistory.length + 1,
            userId: user.id,
            email: user.email,
            timestamp: new Date().toISOString(),
            userAgent: req.headers['user-agent'] || 'AutoFactura Android App',
            ipAddress: req.ip || req.connection.remoteAddress
        };
        loginHistory.push(loginRecord);

        // Generează token JWT
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Autentificare reușită',
            token: token,
            user: {
                id: user.id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                companyName: user.companyName
            }
        });
    } catch (error) {
        console.error('Eroare la autentificare:', error);
        res.status(500).json({ error: 'Eroare la autentificare' });
    }
});

// 3. Obține profilul utilizatorului
app.get('/api/profile', authenticateToken, (req, res) => {
    try {
        const user = users.find(u => u.id === req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'Utilizator nu a fost găsit' });
        }

        res.json({
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            companyName: user.companyName,
            cui: user.cui,
            registrationNumber: user.registrationNumber,
            caenCode: user.caenCode,
            legalForm: user.legalForm,
            address: user.address,
            phone: user.phone,
            website: user.website,
            isVatPayer: user.isVatPayer,
            vatNumber: user.vatNumber,
            countryCode: user.countryCode,
            iban: user.iban,
            bankName: user.bankName,
            swiftCode: user.swiftCode,
            legalRepresentativeName: user.legalRepresentativeName,
            legalRepresentativePosition: user.legalRepresentativePosition,
            logoPath: user.logoPath,
            isAutoInvoiceEnabled: user.isAutoInvoiceEnabled,
            defaultVatRate: user.defaultVatRate
        });
    } catch (error) {
        console.error('Eroare la obținerea profilului:', error);
        res.status(500).json({ error: 'Eroare la obținerea profilului' });
    }
});

// 4. Actualizează profilul utilizatorului
app.put('/api/profile', authenticateToken, (req, res) => {
    try {
        const userIndex = users.findIndex(u => u.id === req.user.userId);
        if (userIndex === -1) {
            return res.status(404).json({ error: 'Utilizator nu a fost găsit' });
        }

        const updatedData = req.body;
        users[userIndex] = { ...users[userIndex], ...updatedData };

        res.json({
            message: 'Profil actualizat cu succes',
            user: {
                id: users[userIndex].id,
                email: users[userIndex].email,
                firstName: users[userIndex].firstName,
                lastName: users[userIndex].lastName,
                companyName: users[userIndex].companyName
            }
        });
    } catch (error) {
        console.error('Eroare la actualizarea profilului:', error);
        res.status(500).json({ error: 'Eroare la actualizarea profilului' });
    }
});

// 5. Schimbă parola
app.put('/api/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        const userIndex = users.findIndex(u => u.id === req.user.userId);
        if (userIndex === -1) {
            return res.status(404).json({ error: 'Utilizator nu a fost găsit' });
        }

        const user = users[userIndex];
        const isValidPassword = await bcrypt.compare(currentPassword, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Parola curentă este incorectă' });
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        users[userIndex].password = hashedNewPassword;

        res.json({ message: 'Parola a fost schimbată cu succes' });
    } catch (error) {
        console.error('Eroare la schimbarea parolei:', error);
        res.status(500).json({ error: 'Eroare la schimbarea parolei' });
    }
});

// 6. Uitare parolă - funcționalitate reală cu securitate avansată
app.post('/api/forgot-password', forgotPasswordRateLimit, validateForgotPassword, handleValidationErrors, async (req, res) => {
    try {
        const { email } = req.body;

        const user = users.find(u => u.email === email);
        if (!user) {
            return res.status(404).json({ error: 'Email-ul nu a fost găsit' });
        }

        // Generează token unic pentru resetare
        const resetToken = uuidv4();
        const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minute

        // Salvează token-ul
        passwordResetTokens.push({
            token: resetToken,
            userId: user.id,
            email: user.email,
            expiresAt: expiresAt,
            used: false
        });

        // Generează link-ul de resetare
        const resetLink = `${req.protocol}://${req.get('host')}/reset-password?token=${resetToken}`;

        // Trimite email cu link-ul de resetare
        try {
            await emailTransporter.sendMail({
                from: 'AutoFactura <noreply@autofactura.com>',
                to: email,
                subject: 'Resetare Parolă - AutoFactura',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #2c3e50;">Resetare Parolă - AutoFactura</h2>
                        <p>Salut ${user.firstName},</p>
                        <p>Ai solicitat resetarea parolei pentru contul tău AutoFactura.</p>
                        <p>Apasă pe link-ul de mai jos pentru a reseta parola:</p>
                        <a href="${resetLink}" style="background: #3498db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Resetează Parola</a>
                        <p><strong>Link-ul expiră în 30 de minute.</strong></p>
                        <p>Dacă nu ai solicitat această resetare, ignoră acest email.</p>
                        <hr>
                        <p style="color: #7f8c8d; font-size: 12px;">AutoFactura - Sistem de Facturare</p>
                    </div>
                `
            });

            // Adaugă activitate pentru resetare
            const activity = {
                id: userActivity.length + 1,
                type: 'password_reset_requested',
                description: 'Solicitare resetare parolă',
                timestamp: new Date().toISOString(),
                userEmail: email,
                userAgent: req.headers['user-agent'] || 'AutoFactura Android App'
            };
            userActivity.push(activity);

            res.json({ message: 'Link de resetare trimis pe email' });
        } catch (emailError) {
            console.error('Eroare la trimiterea email-ului:', emailError);
            res.status(500).json({ error: 'Eroare la trimiterea email-ului' });
        }
    } catch (error) {
        console.error('Eroare la uitarea parolei:', error);
        res.status(500).json({ error: 'Eroare la uitarea parolei' });
    }
});

// 7. Obține statistici - fără autentificare pentru dashboard
app.get('/api/stats', (req, res) => {
    try {
        // Verifică cache-ul mai întâi
        const cachedStats = cacheUtils.get('dashboard_stats');
        if (cachedStats) {
            performanceLogger.info('Cache hit for dashboard stats');
            return res.json(cachedStats);
        }
        
        // Dacă nu există în cache, calculează și cachează
        const stats = queryOptimizations.getDashboardStats(users, invoices, clients);
        
        // Adaugă statistici suplimentare
        const enhancedStats = {
            ...stats,
            totalLogins: loginHistory.length,
            totalActivity: userActivity.length,
            totalProducts: products.length
        };
        
        cacheUtils.cacheStats(enhancedStats);
        res.json(enhancedStats);
    } catch (error) {
        performanceLogger.error('Eroare la obținerea statisticilor:', error);
        res.status(500).json({ error: 'Eroare la obținerea statisticilor' });
    }
});

// 8. Obține lista utilizatorilor (pentru dashboard)
app.get('/api/users', (req, res) => {
    try {
        const usersList = users.map(user => ({
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            companyName: user.companyName,
            phone: user.phone,
            address: user.address,
            isOnline: user.isOnline,
            lastLogin: user.lastLogin,
            createdAt: user.createdAt
        }));

        res.json(usersList);
    } catch (error) {
        console.error('Eroare la obținerea utilizatorilor:', error);
        res.status(500).json({ error: 'Eroare la obținerea utilizatorilor' });
    }
});

// 9. Obține activitatea recentă (pentru dashboard)
app.get('/api/activity', (req, res) => {
    try {
        // Verifică cache-ul mai întâi
        const cachedActivity = cacheUtils.get('recent_activity');
        if (cachedActivity) {
            performanceLogger.info('Cache hit for recent activity');
            return res.json(cachedActivity);
        }
        
        // Dacă nu există în cache, calculează și cachează
        const activity = queryOptimizations.getRecentActivity(userActivity, 50);
        cacheUtils.cacheActivity(activity);
        
        res.json(activity);
    } catch (error) {
        performanceLogger.error('Eroare la obținerea activității:', error);
        res.status(500).json({ error: 'Eroare la obținerea activității' });
    }
});

// 10. Șterge utilizator (pentru admin)
app.delete('/api/users/:id', (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'Utilizator nu a fost găsit' });
        }

        const user = users[userIndex];
        users.splice(userIndex, 1);

        // Adaugă activitate pentru ștergere
        const activity = {
            id: userActivity.length + 1,
            type: 'user_deleted',
            description: 'Utilizator șters',
            timestamp: new Date().toISOString(),
            userEmail: user.email,
            userAgent: req.headers['user-agent'] || 'Admin Dashboard'
        };
        userActivity.push(activity);

        res.json({ message: 'Utilizator șters cu succes' });
    } catch (error) {
        console.error('Eroare la ștergerea utilizatorului:', error);
        res.status(500).json({ error: 'Eroare la ștergerea utilizatorului' });
    }
});

// 11. Obține utilizatorii online
app.get('/api/users/online', (req, res) => {
    try {
        // Verifică cache-ul mai întâi
        const cachedOnlineUsers = cacheUtils.get('online_users');
        if (cachedOnlineUsers) {
            performanceLogger.info('Cache hit for online users');
            return res.json(cachedOnlineUsers);
        }
        
        // Dacă nu există în cache, calculează și cachează
        const onlineUsers = queryOptimizations.getOnlineUsers(users);
        cacheUtils.cacheOnlineUsers(onlineUsers);
        
        res.json(onlineUsers);
    } catch (error) {
        performanceLogger.error('Eroare la obținerea utilizatorilor online:', error);
        res.status(500).json({ error: 'Eroare la obținerea utilizatorilor online' });
    }
});

// 12. Obține istoricul de login
app.get('/api/login-history', (req, res) => {
    try {
        const history = loginHistory
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, 100); // Ultimele 100 de login-uri

        res.json(history);
    } catch (error) {
        console.error('Eroare la obținerea istoricului de login:', error);
        res.status(500).json({ error: 'Eroare la obținerea istoricului de login' });
    }
});

// 13. Deconectează utilizator (pentru admin)
app.post('/api/users/:id/logout', (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const user = users.find(u => u.id === userId);
        
        if (!user) {
            return res.status(404).json({ error: 'Utilizator nu a fost găsit' });
        }

        user.isOnline = false;

        // Adaugă activitate pentru deconectare
        const activity = {
            id: userActivity.length + 1,
            type: 'user_logout',
            description: 'Utilizator deconectat',
            timestamp: new Date().toISOString(),
            userEmail: user.email,
            userAgent: req.headers['user-agent'] || 'Admin Dashboard'
        };
        userActivity.push(activity);

        res.json({ message: 'Utilizator deconectat cu succes' });
    } catch (error) {
        console.error('Eroare la deconectarea utilizatorului:', error);
        res.status(500).json({ error: 'Eroare la deconectarea utilizatorului' });
    }
});

// 14. Resetare parolă cu token
app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        // Găsește token-ul
        const resetToken = passwordResetTokens.find(t => t.token === token);
        if (!resetToken) {
            return res.status(400).json({ error: 'Token invalid' });
        }

        // Verifică dacă token-ul a expirat
        if (new Date() > resetToken.expiresAt) {
            return res.status(400).json({ error: 'Token expirat' });
        }

        // Verifică dacă token-ul a fost deja folosit
        if (resetToken.used) {
            return res.status(400).json({ error: 'Token deja folosit' });
        }

        // Găsește utilizatorul
        const user = users.find(u => u.id === resetToken.userId);
        if (!user) {
            return res.status(404).json({ error: 'Utilizator nu a fost găsit' });
        }

        // Hash noua parolă
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;

        // Marchează token-ul ca folosit
        resetToken.used = true;

        // Adaugă activitate pentru resetare
        const activity = {
            id: userActivity.length + 1,
            type: 'password_reset_completed',
            description: 'Parolă resetată cu succes',
            timestamp: new Date().toISOString(),
            userEmail: user.email,
            userAgent: req.headers['user-agent'] || 'Web Browser'
        };
        userActivity.push(activity);

        res.json({ message: 'Parola a fost resetată cu succes' });
    } catch (error) {
        console.error('Eroare la resetarea parolei:', error);
        res.status(500).json({ error: 'Eroare la resetarea parolei' });
    }
});

// 15. Verifică token-ul de resetare
app.get('/api/verify-reset-token/:token', (req, res) => {
    try {
        const { token } = req.params;

        const resetToken = passwordResetTokens.find(t => t.token === token);
        if (!resetToken) {
            return res.status(400).json({ error: 'Token invalid' });
        }

        if (new Date() > resetToken.expiresAt) {
            return res.status(400).json({ error: 'Token expirat' });
        }

        if (resetToken.used) {
            return res.status(400).json({ error: 'Token deja folosit' });
        }

        res.json({ valid: true, email: resetToken.email });
    } catch (error) {
        console.error('Eroare la verificarea token-ului:', error);
        res.status(500).json({ error: 'Eroare la verificarea token-ului' });
    }
});

// 16. Actualizează profilul utilizatorului
app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const {
            firstName,
            lastName,
            companyName,
            cui,
            registrationNumber,
            caenCode,
            legalForm,
            address,
            phone,
            website,
            isVatPayer,
            vatNumber,
            countryCode,
            iban,
            bankName,
            swiftCode,
            legalRepresentativeName,
            legalRepresentativePosition,
            logoPath,
            isAutoInvoiceEnabled,
            defaultVatRate
        } = req.body;

        const user = users.find(u => u.id === userId);
        if (!user) {
            return res.status(404).json({ error: 'Utilizator nu a fost găsit' });
        }

        // Actualizează câmpurile
        if (firstName) user.firstName = firstName;
        if (lastName) user.lastName = lastName;
        if (companyName) user.companyName = companyName;
        if (cui) user.cui = cui;
        if (registrationNumber) user.registrationNumber = registrationNumber;
        if (caenCode) user.caenCode = caenCode;
        if (legalForm) user.legalForm = legalForm;
        if (address) user.address = address;
        if (phone) user.phone = phone;
        if (website) user.website = website;
        if (isVatPayer !== undefined) user.isVatPayer = isVatPayer;
        if (vatNumber) user.vatNumber = vatNumber;
        if (countryCode) user.countryCode = countryCode;
        if (iban) user.iban = iban;
        if (bankName) user.bankName = bankName;
        if (swiftCode) user.swiftCode = swiftCode;
        if (legalRepresentativeName) user.legalRepresentativeName = legalRepresentativeName;
        if (legalRepresentativePosition) user.legalRepresentativePosition = legalRepresentativePosition;
        if (logoPath) user.logoPath = logoPath;
        if (isAutoInvoiceEnabled !== undefined) user.isAutoInvoiceEnabled = isAutoInvoiceEnabled;
        if (defaultVatRate !== undefined) user.defaultVatRate = defaultVatRate;

        // Adaugă activitate pentru actualizare profil
        const activity = {
            id: userActivity.length + 1,
            type: 'profile_updated',
            description: 'Profil actualizat',
            timestamp: new Date().toISOString(),
            userEmail: user.email,
            userAgent: req.headers['user-agent'] || 'AutoFactura Android App'
        };
        userActivity.push(activity);

        res.json({
            message: 'Profil actualizat cu succes',
            user: {
                id: user.id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                companyName: user.companyName,
                cui: user.cui,
                registrationNumber: user.registrationNumber,
                caenCode: user.caenCode,
                legalForm: user.legalForm,
                address: user.address,
                phone: user.phone,
                website: user.website,
                isVatPayer: user.isVatPayer,
                vatNumber: user.vatNumber,
                countryCode: user.countryCode,
                iban: user.iban,
                bankName: user.bankName,
                swiftCode: user.swiftCode,
                legalRepresentativeName: user.legalRepresentativeName,
                legalRepresentativePosition: user.legalRepresentativePosition,
                logoPath: user.logoPath,
                isAutoInvoiceEnabled: user.isAutoInvoiceEnabled,
                defaultVatRate: user.defaultVatRate
            }
        });
    } catch (error) {
        console.error('Eroare la actualizarea profilului:', error);
        res.status(500).json({ error: 'Eroare la actualizarea profilului' });
    }
});

// Servirea paginii de resetare parolă
app.get('/reset-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'reset-password.html'));
});

// ==================== INTERFAȚĂ WEB PENTRU CLIENȚI ====================

// Servirea paginilor pentru clienți
app.get('/client-login', (req, res) => {
    res.sendFile(path.join(__dirname, 'client-login.html'));
});

app.get('/client-signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'client-signup.html'));
});

app.get('/client-forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'client-forgot-password.html'));
});

app.get('/client-dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'client-dashboard.html'));
});

// Endpoint pentru verificarea token-ului
app.get('/api/verify-token', authenticateToken, (req, res) => {
    try {
        const user = users.find(u => u.id === req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'Utilizator nu a fost găsit' });
        }

        res.json({
            valid: true,
            user: {
                id: user.id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                companyName: user.companyName
            }
        });
    } catch (error) {
        console.error('Eroare la verificarea token-ului:', error);
        res.status(500).json({ error: 'Eroare la verificarea token-ului' });
    }
});

// ==================== SISTEM CAPTCHA ====================

// Generează CAPTCHA nou
app.get('/api/captcha/generate', (req, res) => {
    try {
        const captcha = generateCaptcha();
        res.json({
            success: true,
            captcha: captcha
        });
    } catch (error) {
        console.error('Eroare la generarea CAPTCHA:', error);
        res.status(500).json({ error: 'Eroare la generarea CAPTCHA' });
    }
});

// Verifică CAPTCHA
app.post('/api/captcha/verify', (req, res) => {
    try {
        const { token, answer } = req.body;
        
        if (!token || !answer) {
            return res.status(400).json({ error: 'Token și răspuns sunt obligatorii' });
        }
        
        const result = verifyCaptcha(token, answer);
        res.json(result);
    } catch (error) {
        console.error('Eroare la verificarea CAPTCHA:', error);
        res.status(500).json({ error: 'Eroare la verificarea CAPTCHA' });
    }
});

// Statistici CAPTCHA (pentru admin)
app.get('/api/captcha/stats', authenticateToken, (req, res) => {
    try {
        const stats = getCaptchaStats();
        res.json({
            success: true,
            stats: stats
        });
    } catch (error) {
        console.error('Eroare la obținerea statisticilor CAPTCHA:', error);
        res.status(500).json({ error: 'Eroare la obținerea statisticilor CAPTCHA' });
    }
});

// ==================== SISTEM DE FACTURARE ====================

// 17. Obține toți clienții unui utilizator
app.get('/api/clients', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const userClients = clients.filter(client => client.userId === userId);
        
        res.json(userClients);
    } catch (error) {
        console.error('Eroare la obținerea clienților:', error);
        res.status(500).json({ error: 'Eroare la obținerea clienților' });
    }
});

// 18. Adaugă client nou
app.post('/api/clients', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const {
            name,
            email,
            phone,
            address,
            cui,
            registrationNumber,
            isVatPayer,
            vatNumber,
            countryCode,
            notes
        } = req.body;

        const newClient = {
            id: clients.length + 1,
            userId: userId,
            name,
            email,
            phone,
            address,
            cui,
            registrationNumber,
            isVatPayer: isVatPayer || false,
            vatNumber,
            countryCode: countryCode || 'RO',
            notes,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        clients.push(newClient);

        // Adaugă activitate
        const activity = {
            id: userActivity.length + 1,
            type: 'client_created',
            description: 'Client nou adăugat',
            timestamp: new Date().toISOString(),
            userEmail: req.user.email,
            userAgent: req.headers['user-agent'] || 'AutoFactura Android App',
            details: { clientName: name }
        };
        userActivity.push(activity);

        res.json({
            message: 'Client adăugat cu succes',
            client: newClient
        });
    } catch (error) {
        console.error('Eroare la adăugarea clientului:', error);
        res.status(500).json({ error: 'Eroare la adăugarea clientului' });
    }
});

// 19. Actualizează client
app.put('/api/clients/:id', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const clientId = parseInt(req.params.id);
        const clientIndex = clients.findIndex(c => c.id === clientId && c.userId === userId);
        
        if (clientIndex === -1) {
            return res.status(404).json({ error: 'Client nu a fost găsit' });
        }

        const {
            name,
            email,
            phone,
            address,
            cui,
            registrationNumber,
            isVatPayer,
            vatNumber,
            countryCode,
            notes
        } = req.body;

        // Actualizează clientul
        clients[clientIndex] = {
            ...clients[clientIndex],
            name,
            email,
            phone,
            address,
            cui,
            registrationNumber,
            isVatPayer: isVatPayer || false,
            vatNumber,
            countryCode: countryCode || 'RO',
            notes,
            updatedAt: new Date().toISOString()
        };

        // Adaugă activitate
        const activity = {
            id: userActivity.length + 1,
            type: 'client_updated',
            description: 'Client actualizat',
            timestamp: new Date().toISOString(),
            userEmail: req.user.email,
            userAgent: req.headers['user-agent'] || 'AutoFactura Android App',
            details: { clientName: name }
        };
        userActivity.push(activity);

        res.json({
            message: 'Client actualizat cu succes',
            client: clients[clientIndex]
        });
    } catch (error) {
        console.error('Eroare la actualizarea clientului:', error);
        res.status(500).json({ error: 'Eroare la actualizarea clientului' });
    }
});

// 20. Șterge client
app.delete('/api/clients/:id', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const clientId = parseInt(req.params.id);
        const clientIndex = clients.findIndex(c => c.id === clientId && c.userId === userId);
        
        if (clientIndex === -1) {
            return res.status(404).json({ error: 'Client nu a fost găsit' });
        }

        const client = clients[clientIndex];
        clients.splice(clientIndex, 1);

        // Adaugă activitate
        const activity = {
            id: userActivity.length + 1,
            type: 'client_deleted',
            description: 'Client șters',
            timestamp: new Date().toISOString(),
            userEmail: req.user.email,
            userAgent: req.headers['user-agent'] || 'AutoFactura Android App',
            details: { clientName: client.name }
        };
        userActivity.push(activity);

        res.json({ message: 'Client șters cu succes' });
    } catch (error) {
        console.error('Eroare la ștergerea clientului:', error);
        res.status(500).json({ error: 'Eroare la ștergerea clientului' });
    }
});

// 21. Obține toate produsele unui utilizator
app.get('/api/products', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const userProducts = products.filter(product => product.userId === userId);
        
        res.json(userProducts);
    } catch (error) {
        console.error('Eroare la obținerea produselor:', error);
        res.status(500).json({ error: 'Eroare la obținerea produselor' });
    }
});

// 22. Adaugă produs nou
app.post('/api/products', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const {
            name,
            description,
            price,
            vatRate,
            unit,
            category,
            sku
        } = req.body;

        const newProduct = {
            id: products.length + 1,
            userId: userId,
            name,
            description,
            price: parseFloat(price),
            vatRate: parseFloat(vatRate) || 19.0,
            unit: unit || 'buc',
            category: category || 'General',
            sku,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        products.push(newProduct);

        // Adaugă activitate
        const activity = {
            id: userActivity.length + 1,
            type: 'product_created',
            description: 'Produs nou adăugat',
            timestamp: new Date().toISOString(),
            userEmail: req.user.email,
            userAgent: req.headers['user-agent'] || 'AutoFactura Android App',
            details: { productName: name }
        };
        userActivity.push(activity);

        res.json({
            message: 'Produs adăugat cu succes',
            product: newProduct
        });
    } catch (error) {
        console.error('Eroare la adăugarea produsului:', error);
        res.status(500).json({ error: 'Eroare la adăugarea produsului' });
    }
});

// 23. Actualizează produs
app.put('/api/products/:id', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const productId = parseInt(req.params.id);
        const productIndex = products.findIndex(p => p.id === productId && p.userId === userId);
        
        if (productIndex === -1) {
            return res.status(404).json({ error: 'Produs nu a fost găsit' });
        }

        const {
            name,
            description,
            price,
            vatRate,
            unit,
            category,
            sku
        } = req.body;

        // Actualizează produsul
        products[productIndex] = {
            ...products[productIndex],
            name,
            description,
            price: parseFloat(price),
            vatRate: parseFloat(vatRate) || 19.0,
            unit: unit || 'buc',
            category: category || 'General',
            sku,
            updatedAt: new Date().toISOString()
        };

        // Adaugă activitate
        const activity = {
            id: userActivity.length + 1,
            type: 'product_updated',
            description: 'Produs actualizat',
            timestamp: new Date().toISOString(),
            userEmail: req.user.email,
            userAgent: req.headers['user-agent'] || 'AutoFactura Android App',
            details: { productName: name }
        };
        userActivity.push(activity);

        res.json({
            message: 'Produs actualizat cu succes',
            product: products[productIndex]
        });
    } catch (error) {
        console.error('Eroare la actualizarea produsului:', error);
        res.status(500).json({ error: 'Eroare la actualizarea produsului' });
    }
});

// 24. Șterge produs
app.delete('/api/products/:id', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const productId = parseInt(req.params.id);
        const productIndex = products.findIndex(p => p.id === productId && p.userId === userId);
        
        if (productIndex === -1) {
            return res.status(404).json({ error: 'Produs nu a fost găsit' });
        }

        const product = products[productIndex];
        products.splice(productIndex, 1);

        // Adaugă activitate
        const activity = {
            id: userActivity.length + 1,
            type: 'product_deleted',
            description: 'Produs șters',
            timestamp: new Date().toISOString(),
            userEmail: req.user.email,
            userAgent: req.headers['user-agent'] || 'AutoFactura Android App',
            details: { productName: product.name }
        };
        userActivity.push(activity);

        res.json({ message: 'Produs șters cu succes' });
    } catch (error) {
        console.error('Eroare la ștergerea produsului:', error);
        res.status(500).json({ error: 'Eroare la ștergerea produsului' });
    }
});

// 25. Obține toate facturile unui utilizator
app.get('/api/invoices', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const userInvoices = invoices.filter(invoice => invoice.userId === userId);
        
        // Sortează după data de emisie (cele mai recente primul)
        userInvoices.sort((a, b) => new Date(b.issueDate) - new Date(a.issueDate));
        
        res.json(userInvoices);
    } catch (error) {
        console.error('Eroare la obținerea facturilor:', error);
        res.status(500).json({ error: 'Eroare la obținerea facturilor' });
    }
});

// 26. Obține o factură specifică
app.get('/api/invoices/:id', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const invoiceId = parseInt(req.params.id);
        const invoice = invoices.find(i => i.id === invoiceId && i.userId === userId);
        
        if (!invoice) {
            return res.status(404).json({ error: 'Factură nu a fost găsită' });
        }
        
        res.json(invoice);
    } catch (error) {
        console.error('Eroare la obținerea facturii:', error);
        res.status(500).json({ error: 'Eroare la obținerea facturii' });
    }
});

// 27. Creează factură nouă
app.post('/api/invoices', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const {
            clientId,
            invoiceNumber,
            issueDate,
            dueDate,
            items,
            notes,
            paymentMethod,
            currency
        } = req.body;

        // Verifică dacă clientul există
        const client = clients.find(c => c.id === clientId && c.userId === userId);
        if (!client) {
            return res.status(404).json({ error: 'Client nu a fost găsit' });
        }

        // Calculează totalurile
        let subtotal = 0;
        let totalVat = 0;
        let total = 0;

        const processedItems = items.map(item => {
            const itemTotal = item.quantity * item.price;
            const itemVat = itemTotal * (item.vatRate / 100);
            const itemTotalWithVat = itemTotal + itemVat;

            subtotal += itemTotal;
            totalVat += itemVat;
            total += itemTotalWithVat;

            return {
                ...item,
                total: itemTotal,
                vatAmount: itemVat,
                totalWithVat: itemTotalWithVat
            };
        });

        const newInvoice = {
            id: invoices.length + 1,
            userId: userId,
            clientId: clientId,
            invoiceNumber: invoiceNumber || `INV-${Date.now()}`,
            issueDate: issueDate || new Date().toISOString(),
            dueDate: dueDate || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
            items: processedItems,
            subtotal: subtotal,
            totalVat: totalVat,
            total: total,
            notes: notes || '',
            paymentMethod: paymentMethod || 'Transfer bancar',
            currency: currency || 'RON',
            status: 'draft', // draft, sent, paid, overdue
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        invoices.push(newInvoice);

        // Adaugă activitate
        const activity = {
            id: userActivity.length + 1,
            type: 'invoice_created',
            description: 'Factură nouă creată',
            timestamp: new Date().toISOString(),
            userEmail: req.user.email,
            userAgent: req.headers['user-agent'] || 'AutoFactura Android App',
            details: { 
                invoiceNumber: newInvoice.invoiceNumber,
                clientName: client.name,
                total: total
            }
        };
        userActivity.push(activity);

        res.json({
            message: 'Factură creată cu succes',
            invoice: newInvoice
        });
    } catch (error) {
        console.error('Eroare la crearea facturii:', error);
        res.status(500).json({ error: 'Eroare la crearea facturii' });
    }
});

// 28. Actualizează factură
app.put('/api/invoices/:id', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const invoiceId = parseInt(req.params.id);
        const invoiceIndex = invoices.findIndex(i => i.id === invoiceId && i.userId === userId);
        
        if (invoiceIndex === -1) {
            return res.status(404).json({ error: 'Factură nu a fost găsită' });
        }

        const {
            clientId,
            invoiceNumber,
            issueDate,
            dueDate,
            items,
            notes,
            paymentMethod,
            currency,
            status
        } = req.body;

        // Verifică dacă clientul există
        const client = clients.find(c => c.id === clientId && c.userId === userId);
        if (!client) {
            return res.status(404).json({ error: 'Client nu a fost găsit' });
        }

        // Calculează totalurile
        let subtotal = 0;
        let totalVat = 0;
        let total = 0;

        const processedItems = items.map(item => {
            const itemTotal = item.quantity * item.price;
            const itemVat = itemTotal * (item.vatRate / 100);
            const itemTotalWithVat = itemTotal + itemVat;

            subtotal += itemTotal;
            totalVat += itemVat;
            total += itemTotalWithVat;

            return {
                ...item,
                total: itemTotal,
                vatAmount: itemVat,
                totalWithVat: itemTotalWithVat
            };
        });

        // Actualizează factura
        invoices[invoiceIndex] = {
            ...invoices[invoiceIndex],
            clientId: clientId,
            invoiceNumber: invoiceNumber || invoices[invoiceIndex].invoiceNumber,
            issueDate: issueDate || invoices[invoiceIndex].issueDate,
            dueDate: dueDate || invoices[invoiceIndex].dueDate,
            items: processedItems,
            subtotal: subtotal,
            totalVat: totalVat,
            total: total,
            notes: notes || '',
            paymentMethod: paymentMethod || invoices[invoiceIndex].paymentMethod,
            currency: currency || invoices[invoiceIndex].currency,
            status: status || invoices[invoiceIndex].status,
            updatedAt: new Date().toISOString()
        };

        // Adaugă activitate
        const activity = {
            id: userActivity.length + 1,
            type: 'invoice_updated',
            description: 'Factură actualizată',
            timestamp: new Date().toISOString(),
            userEmail: req.user.email,
            userAgent: req.headers['user-agent'] || 'AutoFactura Android App',
            details: { 
                invoiceNumber: invoices[invoiceIndex].invoiceNumber,
                clientName: client.name
            }
        };
        userActivity.push(activity);

        res.json({
            message: 'Factură actualizată cu succes',
            invoice: invoices[invoiceIndex]
        });
    } catch (error) {
        console.error('Eroare la actualizarea facturii:', error);
        res.status(500).json({ error: 'Eroare la actualizarea facturii' });
    }
});

// 29. Șterge factură
app.delete('/api/invoices/:id', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const invoiceId = parseInt(req.params.id);
        const invoiceIndex = invoices.findIndex(i => i.id === invoiceId && i.userId === userId);
        
        if (invoiceIndex === -1) {
            return res.status(404).json({ error: 'Factură nu a fost găsită' });
        }

        const invoice = invoices[invoiceIndex];
        const client = clients.find(c => c.id === invoice.clientId);
        invoices.splice(invoiceIndex, 1);

        // Adaugă activitate
        const activity = {
            id: userActivity.length + 1,
            type: 'invoice_deleted',
            description: 'Factură ștearsă',
            timestamp: new Date().toISOString(),
            userEmail: req.user.email,
            userAgent: req.headers['user-agent'] || 'AutoFactura Android App',
            details: { 
                invoiceNumber: invoice.invoiceNumber,
                clientName: client?.name || 'Client necunoscut'
            }
        };
        userActivity.push(activity);

        res.json({ message: 'Factură ștearsă cu succes' });
    } catch (error) {
        console.error('Eroare la ștergerea facturii:', error);
        res.status(500).json({ error: 'Eroare la ștergerea facturii' });
    }
});

// 30. Obține statistici facturare
app.get('/api/invoices/stats', authenticateToken, (req, res) => {
    try {
        const userId = req.user.userId;
        const userInvoices = invoices.filter(invoice => invoice.userId === userId);
        
        const totalInvoices = userInvoices.length;
        const totalRevenue = userInvoices.reduce((sum, invoice) => sum + invoice.total, 0);
        const paidInvoices = userInvoices.filter(invoice => invoice.status === 'paid').length;
        const overdueInvoices = userInvoices.filter(invoice => {
            return invoice.status !== 'paid' && new Date(invoice.dueDate) < new Date();
        }).length;
        
        // Statistici pe luni
        const monthlyStats = {};
        userInvoices.forEach(invoice => {
            const month = new Date(invoice.issueDate).toISOString().substring(0, 7); // YYYY-MM
            if (!monthlyStats[month]) {
                monthlyStats[month] = { count: 0, revenue: 0 };
            }
            monthlyStats[month].count++;
            monthlyStats[month].revenue += invoice.total;
        });
        
        res.json({
            totalInvoices,
            totalRevenue,
            paidInvoices,
            overdueInvoices,
            monthlyStats
        });
    } catch (error) {
        console.error('Eroare la obținerea statisticilor facturare:', error);
        res.status(500).json({ error: 'Eroare la obținerea statisticilor facturare' });
    }
});

// Cleanup și optimizări la startup
console.log('🔧 Inițializare optimizări...');

// Actualizează indexurile virtuale
virtualIndexes.updateIndexes(users, userActivity, invoices);

// Cleanup periodic pentru cache și memory
setInterval(() => {
    cleanup();
    cleanupOptimizations();
    virtualIndexes.updateIndexes(users, userActivity, invoices);
}, 300000); // La fiecare 5 minute

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🛑 Server se oprește...');
    cleanup();
    cleanupOptimizations();
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('🛑 Server se oprește...');
    cleanup();
    cleanupOptimizations();
    process.exit(0);
});

// Pornire server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server AutoFactura SIMPLU pornit pe portul ${PORT}`);
    console.log(`📱 API disponibil la: http://localhost:${PORT}/api`);
    console.log(`🌐 Interfața web la: http://localhost:${PORT}`);
    console.log(`📊 Dashboard la: http://localhost:${PORT}/dashboard`);
    console.log(`🌍 Server accesibil de pe orice IP din rețea`);
    console.log(`📱 Pentru dispozitive Android, folosește IP-ul computerului: http://[IP_COMPUTER]:${PORT}/api`);
    console.log(`⚡ Optimizări de performanță activate!`);
    console.log(`📊 Monitoring și cache activat!`);
});
