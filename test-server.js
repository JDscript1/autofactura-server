const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Ruta de test
app.get('/', (req, res) => {
    res.send(`
        <html>
            <head><title>AutoFactura Test</title></head>
            <body>
                <h1>🚀 AutoFactura Server Test</h1>
                <p>Serverul funcționează!</p>
                <p>Timestamp: ${new Date().toISOString()}</p>
            </body>
        </html>
    `);
});

// Ruta API de test
app.get('/api/test', (req, res) => {
    res.json({ 
        message: 'API funcționează!', 
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Test Server pornit pe portul ${PORT}`);
    console.log(`📱 Test disponibil la: http://localhost:${PORT}`);
});
