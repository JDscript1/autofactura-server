const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'autofactura_secret_key_2024';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

// Baza de date simplă în memorie (pentru test)
let users = [
    {
        id: 1,
        email: 'test@example.com',
        password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
        firstName: 'Test',
        lastName: 'User',
        companyName: 'Test Company'
    }
];

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
            defaultVatRate
        };

        users.push(newUser);

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

// 2. Autentificare utilizator
app.post('/api/login', async (req, res) => {
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

// 6. Uitare parolă
app.post('/api/forgot-password', (req, res) => {
    try {
        const { email } = req.body;

        const user = users.find(u => u.email === email);
        if (!user) {
            return res.status(404).json({ error: 'Email-ul nu a fost găsit' });
        }

        // În producție, aici ar trebui să trimiți un email cu link-ul de resetare
        res.json({ message: 'Link de resetare trimis pe email' });
    } catch (error) {
        console.error('Eroare la uitarea parolei:', error);
        res.status(500).json({ error: 'Eroare la uitarea parolei' });
    }
});

// 7. Obține statistici - fără autentificare pentru dashboard
app.get('/api/stats', (req, res) => {
    try {
        const totalUsers = users.length;

        res.json({
            totalUsers: totalUsers,
            totalLogins: 0, // Nu avem tracking pentru login-uri în această versiune simplă
            activeUsers: totalUsers // Presupunem că toți utilizatorii sunt activi
        });
    } catch (error) {
        console.error('Eroare la obținerea statisticilor:', error);
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
            address: user.address
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
        // În această versiune simplă, returnăm o activitate mock
        const activity = [
            {
                id: 1,
                type: 'user_registration',
                description: 'Utilizator nou înregistrat',
                timestamp: new Date().toISOString(),
                userEmail: 'test@example.com'
            }
        ];

        res.json(activity);
    } catch (error) {
        console.error('Eroare la obținerea activității:', error);
        res.status(500).json({ error: 'Eroare la obținerea activității' });
    }
});

// Pornire server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server AutoFactura SIMPLU pornit pe portul ${PORT}`);
    console.log(`📱 API disponibil la: http://localhost:${PORT}/api`);
    console.log(`🌐 Interfața web la: http://localhost:${PORT}`);
    console.log(`📊 Dashboard la: http://localhost:${PORT}/dashboard`);
    console.log(`🌍 Server accesibil de pe orice IP din rețea`);
    console.log(`📱 Pentru dispozitive Android, folosește IP-ul computerului: http://[IP_COMPUTER]:${PORT}/api`);
});
