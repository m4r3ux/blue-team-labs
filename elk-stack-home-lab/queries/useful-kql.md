# ELK STACK HOME LAB

## Comandos KQL Úteis — Kibana / Elastic / SIEM

Ubuntu 22.04 + Windows 10 Agent | Winlogbeat + Sysmon | Kibana SIEM

---

# Pipeline e Verificação Inicial

## Todos os eventos

```kql
*
```

### Apenas logs do Windows

```kql
host.os.type: windows
```

### Eventos do Sysmon

```kql
event.provider: "Microsoft-Windows-Sysmon"
```

### Eventos do Security Log

```kql
log.level: information AND winlog.channel: Security
```

### Eventos PowerShell

```kql
winlog.channel: "Microsoft-Windows-PowerShell/Operational"
```

### Ver datasets ativos

```kql
event.dataset: *
```

## Login / Autenticação

### Login bem-sucedido

```kql
event.code: 4624
```

### Falha de login (Brute Force)

```kql
event.code: 4625
```

### Falha de login + usuário específico

```kql
event.code: 4625 AND winlog.event_data.TargetUserName: "Administrator"
```

### Falha de login + senha incorreta

```kql
event.code: 4625 AND winlog.event_data.SubStatus: "0xc000006a"
```

### Usuário inexistente

```kql
event.code: 4625 AND winlog.event_data.SubStatus: "0xc0000064"
```

### Conta bloqueada

```kql
event.code: 4740
```

### Logins remotos (RDP)

```kql
event.code: 4624 AND winlog.logon.type: 10
```

### Logins de rede (SMB)

```kql
event.code: 4624 AND winlog.logon.type: 3
```

### Credenciais explícitas

```kql
event.code: 4648
```

### Validação NTLM

```kql
event.code: 4776
```

## Processos (Sysmon)

### Process Creation

```kql
event.code: 1 AND event.provider: "Microsoft-Windows-Sysmon"
```

### CMD.exe executado

```kql
event.code: 1 AND process.name: "cmd.exe"
```

### PowerShell executado

```kql
event.code: 1 AND process.name: "powershell.exe"
```

### EncodedCommand

```kql
event.code: 1 AND winlog.event_data.CommandLine: *EncodedCommand*
```

### ExecutionPolicy Bypass

```kql
event.code: 1 AND winlog.event_data.CommandLine: *Bypass*
```

### PowerShell suspeito

```kql
event.code: 1 AND process.name: "powershell.exe" AND (
    winlog.event_data.CommandLine: *EncodedCommand* OR
    winlog.event_data.CommandLine: *Bypass*
)
```

### Parent Process suspeito

```kql
event.code: 1 AND winlog.event_data.ParentImage: *powershell.exe
```

### Processos iniciados pelo Office

```kql
event.code: 1 AND (
    winlog.event_data.ParentImage: *WINWORD.EXE OR
    winlog.event_data.ParentImage: *EXCEL.EXE
)
```

## Reconhecimento (Discovery)

### whoami

```kql
event.code: 1 AND winlog.event_data.CommandLine: *whoami*
```

### net user

```kql
event.code: 1 AND winlog.event_data.CommandLine: *net user*
```

### net localgroup

```kql
event.code: 1 AND winlog.event_data.CommandLine: *localgroup*
```

### ipconfig

```kql
event.code: 1 AND winlog.event_data.CommandLine: *ipconfig*
```

### netstat

```kql
event.code: 1 AND winlog.event_data.CommandLine: *netstat*
```

### tasklist

```kql
event.code: 1 AND winlog.event_data.CommandLine: *tasklist*
```

## Persistência

### Usuário criado

```kql
event.code: 4720
```

### Usuário adicionado ao grupo admin

```kql
event.code: 4732
```

### Novo usuário backdoor

```kql
event.code: 4720 AND winlog.event_data.TargetUserName: "backdoor"
```

## Rede (Sysmon)

### Conexões de rede

```kql
event.code: 3
```

### Conexões HTTP

```kql
event.code: 3 AND destination.port: 80
```

### Conexões HTTPS

```kql
event.code: 3 AND destination.port: 443
```

### Conexões externas suspeitas

```kql
event.code: 3 AND NOT destination.ip: (
    "10.*" OR
    "172.16.*" OR
    "192.168.*"
)
```

## Arquivos

### Arquivos criados

```kql
event.code: 11
```

### Arquivos .exe criados

```kql
event.code: 11 AND file.extension: "exe"
```

### Arquivos em Temp

```kql
event.code: 11 AND file.path: *Temp*
```

## Registro (Registry)

### Registry modified

```kql
event.code: 13
```

### Persistência Run Key

```kql
event.code: 13 AND registry.path: *CurrentVersion\\Run*
```

## PowerShell Logging

### Script Block Logging

```kql
event.code: 4104
```

### Invoke-WebRequest

```kql
event.code: 4104 AND message: *Invoke-WebRequest*
```

### Download de arquivo

```kql
event.code: 4104 AND message: *OutFile*
```

## LSASS / Credential Dumping

### Acesso ao LSASS

```kql
event.code: 10 AND winlog.event_data.TargetImage: *lsass.exe
```

## Dashboards / Estatísticas

### Top Event IDs

```kql
event.code: *
```

### Eventos por host

```kql
host.name: *
```

### Eventos do último ataque

```kql
@timestamp >= now-15m
```

### Timeline de ataque

```kql
host.name: "WINLAB"
```

### Ordenar:

```kql
@timestamp ASC
```

## Hunting Avançado

### LOLBins

```kql
event.code: 1 AND process.name: (
    "certutil.exe" OR
    "mshta.exe" OR
    "rundll32.exe" OR
    "regsvr32.exe"
)
```

### Certutil download

```kql
event.code: 1 AND winlog.event_data.CommandLine: *certutil*
```

### Base64 em linha de comando

```kql
event.code: 1 AND winlog.event_data.CommandLine: "*==*"
```

### Execução em Temp

```kql
event.code: 1 AND process.executable: *Temp*
```

### Scripts .ps1

```kql
event.code: 1 AND winlog.event_data.CommandLine: *.ps1*
```

## Elasticsearch / Infra

### Cluster Health

```kql
GET /_cluster/health
```

### Índices

```kql
GET _cat/indices?v
```

### Templates

```kql
GET _cat/templates?v
```

### Nodes

```kql
GET _cat/nodes?v
```

## Dicas Operacionais

### Sempre ordenar por timestamp

```kql
@timestamp DESC
```

### Campos mais importantes em investigações

```kql
event.code
host.name
user.name
source.ip
process.name
process.command_line
winlog.event_data.CommandLine
winlog.event_data.ParentImage
hashes
destination.ip
destination.port
```
