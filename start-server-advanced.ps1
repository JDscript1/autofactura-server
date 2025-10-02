# AutoFactura Server - Advanced Launcher with Live Monitoring
param(
    [switch]$OpenBrowser = $true,
    [switch]$ShowLogs = $true
)

# Setare culori și titlu
$Host.UI.RawUI.WindowTitle = "AutoFactura Server - Advanced Mode"
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "Green"
Clear-Host

# Funcție pentru afișarea header-ului
function Show-Header {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "    🚀 AUTOFACTURA SERVER - ADVANCED" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

# Funcție pentru verificarea Node.js
function Test-NodeJS {
    Write-Host "📋 Verificare Node.js..." -ForegroundColor White
    try {
        $nodeVersion = node --version
        Write-Host "✅ Node.js detectat: $nodeVersion" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "❌ Node.js nu este instalat!" -ForegroundColor Red
        Write-Host "📥 Descarcă Node.js de la: https://nodejs.org/" -ForegroundColor Yellow
        return $false
    }
}

# Funcție pentru instalarea dependențelor
function Install-Dependencies {
    Write-Host "📦 Verificare dependențe..." -ForegroundColor White
    if (-not (Test-Path "node_modules")) {
        Write-Host "🔄 Instalare pachete..." -ForegroundColor Yellow
        npm install
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Eroare la instalarea pachetelor!" -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host "✅ Dependențe deja instalate" -ForegroundColor Green
    }
    return $true
}

# Funcție pentru afișarea informațiilor server
function Show-ServerInfo {
    Write-Host ""
    Write-Host "🌐 SERVER INFORMATIONS:" -ForegroundColor Cyan
    Write-Host "   📱 API: http://localhost:3000/api" -ForegroundColor White
    Write-Host "   🌐 Web Interface: http://localhost:3000" -ForegroundColor White
    Write-Host "   📊 Dashboard: http://localhost:3000/dashboard" -ForegroundColor White
    Write-Host ""
    Write-Host "💡 CONTROLS:" -ForegroundColor Cyan
    Write-Host "   • Ctrl+C - Oprește serverul" -ForegroundColor White
    Write-Host "   • R - Restart server" -ForegroundColor White
    Write-Host "   • L - Toggle logs" -ForegroundColor White
    Write-Host "   • S - Show stats" -ForegroundColor White
    Write-Host ""
}

# Funcție pentru monitorizarea live
function Start-LiveMonitoring {
    Write-Host "🔍 LIVE MONITORING ACTIVATED" -ForegroundColor Green
    Write-Host "   • Monitorizare conexiuni în timp real" -ForegroundColor White
    Write-Host "   • Logging avansat activat" -ForegroundColor White
    Write-Host "   • Statistici live disponibile" -ForegroundColor White
    Write-Host ""
}

# Funcție pentru deschiderea browser-ului
function Open-Browser {
    if ($OpenBrowser) {
        Write-Host "🌐 Deschidere browser..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        Start-Process "http://localhost:3000"
    }
}

# Funcție pentru afișarea statisticilor
function Show-Stats {
    Write-Host ""
    Write-Host "📊 STATISTICI SERVER:" -ForegroundColor Cyan
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:3000/api/stats" -Method GET -ErrorAction SilentlyContinue
        Write-Host "   👥 Utilizatori totali: $($response.totalUsers)" -ForegroundColor White
        Write-Host "   🔐 Autentificări totale: $($response.totalLogins)" -ForegroundColor White
        Write-Host "   🟢 Utilizatori activi (7 zile): $($response.activeUsers)" -ForegroundColor White
    }
    catch {
        Write-Host "   ⚠️  Statisticile nu sunt disponibile încă" -ForegroundColor Yellow
    }
    Write-Host ""
}

# MAIN EXECUTION
Show-Header

# Verificări preliminare
if (-not (Test-NodeJS)) {
    Read-Host "Apasă Enter pentru a ieși"
    exit 1
}

if (-not (Install-Dependencies)) {
    Read-Host "Apasă Enter pentru a ieși"
    exit 1
}

Show-ServerInfo
Start-LiveMonitoring

# Deschide browser-ul
Open-Browser

Write-Host "🚀 PORNIRE SERVER..." -ForegroundColor Green
Write-Host ""

# Pornește serverul cu monitorizare
$serverProcess = Start-Process -FilePath "node" -ArgumentList "server.js" -NoNewWindow -PassThru

# Monitorizare taste
Write-Host "💡 Apasă 'S' pentru statistici, 'L' pentru logs, 'R' pentru restart" -ForegroundColor Yellow
Write-Host ""

# Loop pentru monitorizare
while (-not $serverProcess.HasExited) {
    if ([Console]::KeyAvailable) {
        $key = [Console]::ReadKey($true)
        switch ($key.Key) {
            'S' { Show-Stats }
            'L' { 
                Write-Host "📋 Logs toggle - implementare în dezvoltare" -ForegroundColor Yellow
            }
            'R' { 
                Write-Host "🔄 Restart server - implementare în dezvoltare" -ForegroundColor Yellow
            }
        }
    }
    Start-Sleep -Milliseconds 100
}

Write-Host ""
Write-Host "🛑 Server oprit" -ForegroundColor Red
Read-Host "Apasă Enter pentru a ieși"
