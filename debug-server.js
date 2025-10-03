const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware de bază
app.use(express.json());
app.use(express.static(__dirname));

// Rute de test
app.get('/test', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Debug server funcționează!',
        timestamp: new Date().toISOString()
    });
});

app.get('/ping', (req, res) => {
    res.json({ 
        status: 'pong', 
        timestamp: new Date().toISOString() 
    });
});

// Rute pentru dashboard
app.get('/', (req, res) => {
    console.log('🔍 Accesare ruta /');
    try {
        res.sendFile(path.join(__dirname, 'index.html'));
        console.log('✅ index.html trimis cu succes');
    } catch (error) {
        console.error('❌ Eroare la trimiterea index.html:', error);
        res.status(500).json({ error: 'Eroare la încărcarea paginii' });
    }
});

app.get('/dashboard', (req, res) => {
    console.log('🔍 Accesare ruta /dashboard');
    try {
        res.sendFile(path.join(__dirname, 'index.html'));
        console.log('✅ index.html trimis cu succes pentru dashboard');
    } catch (error) {
        console.error('❌ Eroare la trimiterea index.html pentru dashboard:', error);
        res.status(500).json({ error: 'Eroare la încărcarea dashboard-ului' });
    }
});

// Gestionarea erorilor
process.on('uncaughtException', (error) => {
    console.error('❌ Eroare neprinsă:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Promise respinsă:', reason);
    process.exit(1);
});

// Pornire server
try {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`🚀 Debug Server AutoFactura pornit pe portul ${PORT}`);
        console.log(`📱 API disponibil la: http://localhost:${PORT}/api`);
        console.log(`🌐 Interfața web la: http://localhost:${PORT}`);
        console.log(`📊 Dashboard la: http://localhost:${PORT}/dashboard`);
        console.log(`🧪 Test endpoint la: http://localhost:${PORT}/test`);
        console.log(`🏓 Ping endpoint la: http://localhost:${PORT}/ping`);
        console.log(`⚡ Server de debug pentru identificarea problemei!`);
    });
} catch (error) {
    console.error('❌ Eroare la pornirea serverului:', error);
    process.exit(1);
}
