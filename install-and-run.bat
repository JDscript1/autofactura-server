@echo off
title AutoFactura Server - Install & Run
color 0E

echo.
echo ========================================
echo    🚀 AUTOFACTURA SERVER - INSTALL
echo ========================================
echo.

echo 📋 Verificare Node.js...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js nu este instalat!
    echo.
    echo 📥 INSTALARE NODE.JS:
    echo    1. Mergi la: https://nodejs.org/
    echo    2. Descarcă versiunea LTS
    echo    3. Instalează cu setările default
    echo    4. Restart acest script
    echo.
    pause
    exit /b 1
)

echo ✅ Node.js detectat
node --version

echo.
echo 📦 Instalare dependențe...
echo 🔄 Se instalează pachetele necesare...
echo.

npm install
if %errorlevel% neq 0 (
    echo ❌ Eroare la instalarea pachetelor!
    echo.
    echo 🔧 SOLUȚII POSIBILE:
    echo    1. Verifică conexiunea la internet
    echo    2. Rulează ca Administrator
    echo    3. Șterge folderul node_modules și încearcă din nou
    echo.
    pause
    exit /b 1
)

echo ✅ Dependențe instalate cu succes
echo.

echo 🚀 Pornire server...
echo.
echo 📱 API disponibil la: http://localhost:3000/api
echo 🌐 Interfața web la: http://localhost:3000
echo 📊 Dashboard la: http://localhost:3000/dashboard
echo.
echo 💡 Pentru a opri serverul, apasă Ctrl+C
echo.

timeout /t 2 /nobreak >nul
start http://localhost:3000

node server.js

echo.
echo 🛑 Server oprit
pause
