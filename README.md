# Blue Team Labs

![Elasticsearch](https://img.shields.io/badge/Elasticsearch-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)
![Kibana](https://img.shields.io/badge/Kibana-005571?style=for-the-badge&logo=kibana&logoColor=white)
![Windows](https://img.shields.io/badge/Windows_10-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-FF6600?style=for-the-badge&logo=mitre-attack&logoColor=white)

Repositório dedicado à documentação de projetos práticos de Blue Team, SIEM (Security Information and Event Management) e engenharia de detecção de ameaças, construídos em um ambiente de home lab controlado.

Cada laboratório documenta a infraestrutura utilizada, os ataques simulados, as técnicas de detecção implementadas e as evidências coletadas — tudo mapeado diretamente ao framework **MITRE ATT&CK**.

---

## Objetivos do Repositório

*   **Engenharia de Detecção:** Compreender como transformar telemetria bruta (logs de segurança) em alertas acionáveis de alta fidelidade no SIEM.
*   **Simulação de Adversários:** Executar técnicas reais de ataque (Red Team) na máquina vítima para validar se os controles defensivos estão funcionando.
*   **Análise de Logs:** Estudar o comportamento e a estrutura de eventos nativos do Windows (Security Logs) e do Sysmon durante um incidente.

---

## Labs Desenvolvidos

| Lab | Stack Utilizada | Técnicas Cobertas (MITRE ATT&CK) | Status |
| :--- | :--- | :--- | :--- |
| [ELK Stack Home Lab](elk-stack-home-lab/) | Elasticsearch · Kibana · Sysmon · Winlogbeat | Brute Force (T1110), PowerShell Obfuscado (T1059.001), Criação de Conta Local (T1136.001) | 🟢 Concluído |

> 💡 *Novos laboratórios focados em análise de tráfego de rede, firewalls e monitoramento Linux serão adicionados conforme desenvolvidos.*

---

## Estrutura do Repositório

```text
blue-team-labs/
├── README.md                # Documentação principal (este arquivo)
└── elk-stack-home-lab/      # Projeto SIEM com ELK Stack + Windows 10
    ├── architecture/        # Diagramas da rede e fluxo de dados do lab
    ├── queries/             # Regras de detecção em KQL (Kibana Query Language)
    ├── scripts/             # Scripts em PowerShell para simulação de ataques
    └── screenshots/         # Evidências dos alertas disparados no Kibana

---

## Referências

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Elastic Security](https://www.elastic.co/security)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)