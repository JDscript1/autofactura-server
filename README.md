# 🚀 AutoFactura Server - Test Environment

Server local pentru testarea aplicației AutoFactura cu interfață web profesională.

## 📋 Cerințe

- **Node.js** (versiunea 16 sau mai nouă)
- **npm** (vine cu Node.js)

## 🚀 Instalare și Pornire

### Metoda 1: Instalare Automată (Recomandată)
```bash
# Dublu-click pe fișierul:
install-and-run.bat
```

### Metoda 2: Instalare Manuală
```bash
# 1. Instalează dependențele
npm install

# 2. Pornește serverul
npm start
```

### Metoda 3: PowerShell Avansat
```powershell
# Rulează scriptul PowerShell pentru monitorizare avansată
.\start-server-advanced.ps1
```

## 🌐 Accesare

După pornirea serverului, accesează:

- **📱 API**: http://localhost:3000/api
- **🌐 Dashboard**: http://localhost:3000
- **📊 Statistici**: http://localhost:3000/dashboard

## 🔧 API Endpoints

### Autentificare
- `POST /api/register` - Înregistrare utilizator nou
- `POST /api/login` - Autentificare utilizator
- `POST /api/forgot-password` - Recuperare parolă

### Gestionare Utilizatori
- `GET /api/users` - Lista utilizatorilor
- `DELETE /api/users/:id` - Șterge utilizator
- `GET /api/stats` - Statistici server
- `GET /api/login-history` - Istoric autentificări

## 📊 Dashboard Features

- **👥 Gestionare utilizatori** - Vizualizare și ștergere
- **📈 Statistici live** - Utilizatori, autentificări, activitate
- **🔍 Monitorizare activitate** - Istoricul de autentificări
- **📱 Design responsive** - Funcționează pe toate dispozitivele

## 🛠️ Dezvoltare

### Structura Proiectului
```
server/
├── server.js              # Server principal
├── package.json           # Dependențe
├── autofactura.db         # Baza de date SQLite
├── public/
│   └── index.html         # Dashboard web
├── start-server.bat       # Script simplu
├── start-server-advanced.ps1 # Script avansat
└── install-and-run.bat   # Instalare automată
```

### Comenzi Utile
```bash
# Pornire în mod dezvoltare
npm run dev

# Pornire normală
npm start

# Verificare dependențe
npm list
```

## 🔒 Securitate

- **JWT Authentication** - Token-uri securizate
- **Password Hashing** - Parole criptate cu bcrypt
- **CORS** - Configurat pentru aplicația Android
- **Input Validation** - Validare date de intrare

## 📱 Integrare Android

Serverul este pregătit pentru integrarea cu aplicația Android:

1. **Base URL**: `http://localhost:3000/api`
2. **Authentication**: JWT Bearer Token
3. **Content-Type**: `application/json`

### Exemplu de integrare:
```kotlin
// Retrofit service
interface AuthService {
    @POST("login")
    suspend fun login(@Body credentials: LoginRequest): LoginResponse
    
    @POST("register")
    suspend fun register(@Body user: RegisterRequest): RegisterResponse
}
```

## 🐛 Debugging

### Logs Server
Serverul afișează logs în consolă pentru:
- ✅ Conexiuni noi
- 🔐 Autentificări
- 📊 Statistici
- ❌ Erori

### Debugging Android
Pentru debugging din aplicația Android:
1. Verifică că serverul rulează
2. Testează endpoint-urile în browser
3. Verifică logs-urile serverului
4. Folosește Postman pentru testare API

## 🚨 Troubleshooting

### Probleme Comune

**❌ "Node.js nu este instalat"**
- Descarcă Node.js de la https://nodejs.org/
- Instalează versiunea LTS
- Restart terminalul

**❌ "Eroare la instalarea pachetelor"**
- Verifică conexiunea la internet
- Rulează ca Administrator
- Șterge `node_modules` și încearcă din nou

**❌ "Port 3000 este ocupat"**
- Oprește alte aplicații pe portul 3000
- Schimbă portul în `server.js`
- Verifică cu `netstat -an | findstr 3000`

## 📞 Suport

Pentru probleme sau întrebări:
- Verifică logs-urile serverului
- Testează endpoint-urile manual
- Verifică configurația de rețea

---

**🎯 Serverul este pregătit pentru testarea completă a aplicației AutoFactura!**
