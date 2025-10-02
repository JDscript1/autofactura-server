@echo off
title AutoFactura Server - Test Environment
color 0A

echo.
echo ========================================
echo    🚀 AUTOFACTURA SERVER - TEST MODE
echo ========================================
echo.

echo 📋 Verificare Node.js...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js nu este instalat!
    echo 📥 Descarcă Node.js de la: https://nodejs.org/
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
) else (
    echo ✅ Dependențe deja instalate
)

echo.
echo 🚀 Pornire server...
echo.
echo 📱 API disponibil la: http://localhost:3000/api
echo 🌐 Interfața web la: http://localhost:3000
echo 📊 Dashboard la: http://localhost:3000/dashboard
echo.
echo 💡 Pentru a opri serverul, apasă Ctrl+C
echo.

node server.js

echo.
echo 🛑 Server oprit
pause
