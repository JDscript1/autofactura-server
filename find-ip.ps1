# Script pentru găsirea IP-ului computerului
Write-Host "🔍 Căutare IP-uri disponibile pentru server..." -ForegroundColor Green

# Găsește toate IP-urile IPv4
$ipAddresses = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notlike "127.*" -and 
    $_.IPAddress -notlike "169.*" -and
    $_.IPAddress -notlike "::*"
} | Select-Object IPAddress, InterfaceAlias

Write-Host "`n📱 IP-uri disponibile pentru conexiunea Android:" -ForegroundColor Yellow
Write-Host "=" * 50

foreach ($ip in $ipAddresses) {
    Write-Host "🌐 $($ip.IPAddress) - $($ip.InterfaceAlias)" -ForegroundColor Cyan
    Write-Host "   URL pentru aplicație: http://$($ip.IPAddress):3000/api/" -ForegroundColor White
}

Write-Host "`n📋 Instrucțiuni:" -ForegroundColor Green
Write-Host "1. Copiază unul din IP-urile de mai sus" -ForegroundColor White
Write-Host "2. Deschide fișierul: app/src/main/java/com/tudor/autofactura/network/NetworkModule.kt" -ForegroundColor White
Write-Host "3. Înlocuiește IP-ul din funcția getServerUrl() cu IP-ul tău" -ForegroundColor White
Write-Host "4. Recompilează aplicația" -ForegroundColor White

Write-Host "`n🚀 Pentru a porni server-ul, rulează: node server.js" -ForegroundColor Magenta
