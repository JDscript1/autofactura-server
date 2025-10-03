const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Rute simple de test
app.get('/', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Server AutoFactura funcționează!',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

app.get('/test', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Test endpoint funcționează!',
        timestamp: new Date().toISOString()
    });
});

app.get('/ping', (req, res) => {
    res.json({ 
        status: 'pong', 
        timestamp: new Date().toISOString() 
    });
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
        console.log(`🚀 Server AutoFactura TEST pornit pe portul ${PORT}`);
        console.log(`📱 API disponibil la: http://localhost:${PORT}/api`);
        console.log(`🌐 Interfața web la: http://localhost:${PORT}`);
        console.log(`🧪 Test endpoint la: http://localhost:${PORT}/test`);
        console.log(`🏓 Ping endpoint la: http://localhost:${PORT}/ping`);
        console.log(`⚡ Server simplu pentru testare!`);
    });
} catch (error) {
    console.error('❌ Eroare la pornirea serverului:', error);
    process.exit(1);
}
