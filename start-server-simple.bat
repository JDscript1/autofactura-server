@echo off
title AutoFactura Server - Simple Mode
color 0B

echo.
echo ========================================
echo    🚀 AUTOFACTURA SERVER - SIMPLE
echo ========================================
echo.

echo 📋 Verificare Node.js...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js nu este instalat!
    echo 📥 Descarcă Node.js de la: https://nodejs.org/
    echo.
    pause
    exit /b 1
)

echo ✅ Node.js detectat
echo.

echo 📦 Instalare dependențe...
if not exist node_modules (
    echo 🔄 Instalare pachete...
    npm install
    if %errorlevel% neq 0 (
        echo ❌ Eroare la instalarea pachetelor!
        pause
        exit /b 1
    )
    echo ✅ Dependențe instalate cu succes
) else (
    echo ✅ Dependențe deja instalate
)

echo.
echo 🚀 Pornire server...
echo.
echo 📱 API: http://localhost:3000/api
echo 🌐 Web: http://localhost:3000
echo 📊 Dashboard: http://localhost:3000/dashboard
echo.
echo 💡 Pentru a opri serverul, apasă Ctrl+C
echo.

timeout /t 3 /nobreak >nul
start http://localhost:3000

node server.js

echo.
echo 🛑 Server oprit
pause
