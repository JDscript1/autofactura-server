const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'autofactura_secret_key_2024';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Inițializare baza de date
const db = new sqlite3.Database('autofactura.db');

// Creare tabele
db.serialize(() => {
    // Tabela utilizatori
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        firstName TEXT NOT NULL,
        lastName TEXT NOT NULL,
        companyName TEXT NOT NULL,
        cui TEXT NOT NULL,
        registrationNumber TEXT,
        caenCode TEXT,
        legalForm TEXT,
        address TEXT NOT NULL,
        phone TEXT NOT NULL,
        website TEXT,
        isVatPayer BOOLEAN DEFAULT 0,
        vatNumber TEXT,
        countryCode TEXT DEFAULT 'RO',
        iban TEXT NOT NULL,
        bankName TEXT,
        swiftCode TEXT,
        legalRepresentativeName TEXT,
        legalRepresentativePosition TEXT,
        logoPath TEXT,
        isAutoInvoiceEnabled BOOLEAN DEFAULT 0,
        defaultVatRate REAL DEFAULT 19.0,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Tabela pentru istoricul de autentificare
    db.run(`CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER,
        email TEXT,
        loginTime DATETIME DEFAULT CURRENT_TIMESTAMP,
        ipAddress TEXT,
        userAgent TEXT,
        FOREIGN KEY (userId) REFERENCES users (id)
    )`);

    console.log('✅ Baza de date inițializată cu succes');
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

// RUTA PRINCIPALĂ - INTERFAȚA WEB
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API ENDPOINTS

// 1. Înregistrare utilizator nou
app.post('/api/register', async (req, res) => {
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
        db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Eroare la verificarea email-ului' });
            }
            if (row) {
                return res.status(400).json({ error: 'Email-ul există deja' });
            }

            // Hash parola
            const hashedPassword = await bcrypt.hash(password, 10);

            // Inserează utilizatorul nou
            const sql = `INSERT INTO users (
                email, password, firstName, lastName, companyName, cui,
                registrationNumber, caenCode, legalForm, address, phone,
                website, isVatPayer, vatNumber, countryCode, iban,
                bankName, swiftCode, legalRepresentativeName,
                legalRepresentativePosition, logoPath, isAutoInvoiceEnabled,
                defaultVatRate
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

            db.run(sql, [
                email, hashedPassword, firstName, lastName, companyName, cui,
                registrationNumber, caenCode, legalForm, address, phone,
                website, isVatPayer, vatNumber, countryCode, iban,
                bankName, swiftCode, legalRepresentativeName,
                legalRepresentativePosition, logoPath, isAutoInvoiceEnabled,
                defaultVatRate
            ], function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Eroare la crearea utilizatorului' });
                }

                // Generează token JWT
                const token = jwt.sign(
                    { userId: this.lastID, email: email },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );

                res.status(201).json({
                    message: 'Utilizator creat cu succes',
                    token: token,
                    user: {
                        id: this.lastID,
                        email: email,
                        firstName: firstName,
                        lastName: lastName,
                        companyName: companyName
                    }
                });
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Eroare la înregistrare' });
    }
});

// 2. Autentificare utilizator
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Eroare la autentificare' });
        }
        if (!user) {
            return res.status(401).json({ error: 'Email sau parolă incorectă' });
        }

        try {
            const isValidPassword = await bcrypt.compare(password, user.password);
            if (!isValidPassword) {
                return res.status(401).json({ error: 'Email sau parolă incorectă' });
            }

            // Generează token JWT
            const token = jwt.sign(
                { userId: user.id, email: user.email },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            // Salvează istoricul de autentificare
            db.run(
                'INSERT INTO login_history (userId, email, ipAddress, userAgent) VALUES (?, ?, ?, ?)',
                [user.id, email, req.ip, req.get('User-Agent')]
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
            res.status(500).json({ error: 'Eroare la verificarea parolei' });
        }
    });
});

// 3. Recuperare parolă (simulat)
app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;

    db.get('SELECT id FROM users WHERE email = ?', [email], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Eroare la verificarea email-ului' });
        }
        if (!user) {
            return res.status(404).json({ error: 'Email-ul nu există în sistem' });
        }

        // Simulează trimiterea email-ului
        console.log(`📧 Email de recuperare trimis către: ${email}`);
        
        res.json({
            message: 'Email de recuperare trimis cu succes! Verifică-ți inbox-ul.'
        });
    });
});

// 4. Obține toți utilizatorii (pentru interfața web) - fără autentificare pentru dashboard
app.get('/api/users', (req, res) => {
    db.all(`
        SELECT 
            id, email, firstName, lastName, companyName, cui,
            address, phone, website, isVatPayer, createdAt,
            (SELECT COUNT(*) FROM login_history WHERE userId = users.id) as loginCount,
            (SELECT MAX(loginTime) FROM login_history WHERE userId = users.id) as lastLogin
        FROM users 
        ORDER BY createdAt DESC
    `, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Eroare la obținerea utilizatorilor' });
        }
        res.json(rows);
    });
});

// 5. Obține istoricul de autentificare - fără autentificare pentru dashboard
app.get('/api/login-history', (req, res) => {
    db.all(`
        SELECT lh.*, u.firstName, u.lastName, u.companyName
        FROM login_history lh
        JOIN users u ON lh.userId = u.id
        ORDER BY lh.loginTime DESC
        LIMIT 100
    `, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Eroare la obținerea istoricului' });
        }
        res.json(rows);
    });
});

// 6. Șterge utilizator
app.delete('/api/users/:id', authenticateToken, (req, res) => {
    const userId = req.params.id;

    db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Eroare la ștergerea utilizatorului' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Utilizatorul nu a fost găsit' });
        }

        res.json({ message: 'Utilizator șters cu succes' });
    });
});

// 7. Obține statistici - fără autentificare pentru dashboard
app.get('/api/stats', (req, res) => {
    db.get('SELECT COUNT(*) as totalUsers FROM users', (err, userCount) => {
        if (err) {
            return res.status(500).json({ error: 'Eroare la obținerea statisticilor' });
        }

        db.get('SELECT COUNT(*) as totalLogins FROM login_history', (err, loginCount) => {
            if (err) {
                return res.status(500).json({ error: 'Eroare la obținerea statisticilor' });
            }

            db.get(`
                SELECT COUNT(*) as activeUsers 
                FROM users 
                WHERE id IN (
                    SELECT DISTINCT userId 
                    FROM login_history 
                    WHERE loginTime > datetime('now', '-7 days')
                )
            `, (err, activeUsers) => {
                if (err) {
                    return res.status(500).json({ error: 'Eroare la obținerea statisticilor' });
                }

                res.json({
                    totalUsers: userCount.totalUsers,
                    totalLogins: loginCount.totalLogins,
                    activeUsers: activeUsers.activeUsers
                });
            });
        });
    });
});

// Pornire server pe toate interfețele (0.0.0.0)
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server AutoFactura pornit pe portul ${PORT}`);
    console.log(`📱 API disponibil la: http://localhost:${PORT}/api`);
    console.log(`🌐 Interfața web la: http://localhost:${PORT}`);
    console.log(`📊 Dashboard la: http://localhost:${PORT}/dashboard`);
    console.log(`🌍 Server accesibil de pe orice IP din rețea`);
    console.log(`📱 Pentru dispozitive Android, folosește IP-ul computerului: http://[IP_COMPUTER]:${PORT}/api`);
});

// 8. Înregistrează autentificarea (pentru aplicația Android)
app.post('/api/log-login', (req, res) => {
    const { userId, email, loginTime } = req.body;
    
    if (!userId || !email) {
        return res.status(400).json({ error: 'userId și email sunt obligatorii' });
    }
    
    const timestamp = loginTime || new Date().toISOString();
    
    db.run(
        'INSERT INTO login_history (userId, email, loginTime) VALUES (?, ?, ?)',
        [userId, email, timestamp],
        function(err) {
            if (err) {
                console.error('Eroare la înregistrarea autentificării:', err);
                return res.status(500).json({ error: 'Eroare la înregistrarea autentificării' });
            }
            
            console.log(`🔐 Autentificare înregistrată: ${email} la ${timestamp}`);
            res.json({ message: 'Autentificare înregistrată cu succes' });
        }
    );
});

// Gestionare închidere server
process.on('SIGINT', () => {
    console.log('\n🛑 Închidere server...');
    db.close((err) => {
        if (err) {
            console.error('❌ Eroare la închiderea bazei de date:', err.message);
        } else {
            console.log('✅ Baza de date închisă cu succes');
        }
        process.exit(0);
    });
});
