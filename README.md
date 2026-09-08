# SOC Analyst Assistant

Ferramenta educacional em Python que simula um assistente de apoio a um
analista de SOC (Security Operations Center) durante a triagem inicial
de eventos de segurança — leitura de logs, detecção de padrões
suspeitos, classificação de severidade e geração de relatórios de
incidente.

> ⚠️ **Projeto educacional.** Todos os dados utilizados (IPs, usuários,
> eventos) são fictícios e foram criados exclusivamente para
> demonstração. O projeto não substitui um SOC real, um SIEM ou
> qualquer ferramenta de segurança em produção.

## Sobre o projeto

Analistas de SOC lidam diariamente com grandes volumes de logs para
identificar rapidamente atividades potencialmente maliciosas. Este
projeto simula, em pequena escala, a primeira etapa desse processo: a
triagem — transformar linhas de log brutas em eventos estruturados,
aplicar regras de detecção conhecidas (Brute Force, Port Scanning,
Suspicious Login), atribuir uma severidade justificada, relacionar o
achado a uma técnica do MITRE ATT&CK quando aplicável, e produzir um
relatório de incidente pronto para ser revisado por um analista.

## Objetivo

O objetivo é duplo:

- **Educacional**: praticar conceitos de Blue Team (parsing de logs,
  regras de detecção, MITRE ATT&CK, classificação de severidade,
  documentação de incidentes) de forma segura e sem dados reais.
- **Profissional**: servir como peça de portfólio, demonstrando
  organização de código, testes automatizados e boas práticas de
  documentação para vagas de Cibersegurança (SOC/Blue Team, GRC) e
  Infraestrutura de TI.

## Funcionalidades

- Leitura e parsing de arquivos `.log` (autenticação SSH e bloqueios
  de firewall) em eventos estruturados.
- Detecção de **Brute Force** (múltiplas falhas de autenticação para o
  mesmo usuário/origem em uma janela de tempo curta).
- Detecção de **Port Scanning** (múltiplas portas de destino distintas
  acessadas pela mesma origem em uma janela de tempo curta, com base em
  dados simulados de firewall).
- Detecção de **Suspicious Login** (login bem-sucedido com indicadores
  de anomalia: conta sensível, horário incomum ou origem incomum).
- Sinalização explícita de **eventos com dados insuficientes** para uma
  conclusão mais forte, em vez de silêncio ou suposição.
- Classificação de severidade em quatro níveis (`LOW`, `MEDIUM`, `HIGH`,
  `CRITICAL`), sempre acompanhada de uma justificativa textual.
- Associação automática com técnicas do **MITRE ATT&CK** a partir de
  uma base local (`data/mitre_attack.json`).
- Geração de **recomendações de investigação** defensivas (nunca
  ofensivas ou de exploração).
- Geração de **relatórios de incidente** estruturados, visualizáveis na
  interface e exportáveis em `.json`.
- Interface gráfica simples em **Tkinter** para conduzir todo o fluxo
  (selecionar log → analisar → visualizar → gerar relatório).

## Tecnologias

```text
Python 3.10+
Tkinter (interface gráfica)
re (expressões regulares)
JSON (dados e relatórios)
Pytest (testes automatizados)
MITRE ATT&CK (base de referência local)
```

## Arquitetura

O projeto segue um pipeline linear, com responsabilidades bem
separadas entre módulos:

```text
Arquivo de log (.log)
        ↓
  log_analyzer.py        → parsing: linha de log → evento estruturado
        ↓
  alert_classifier.py    → regras de detecção (Brute Force, Port
        ↓                   Scanning, Suspicious Login, dados insuficientes)
  alert_classifier.py    → classificação de severidade + justificativa
        ↓                   + recomendações de investigação
     mitre.py            → associação com técnica(s) MITRE ATT&CK
        ↓
  incident_report.py     → montagem do relatório estruturado
        ↓
      main.py            → interface Tkinter (exibição e exportação)
```

Cada módulo tem uma única responsabilidade e pode ser testado de forma
isolada (ver seção Testes).

## Estrutura do projeto

```text
SOC-Analyst-Assistant/
│
├── data/
│   ├── sample_auth.log        # log de exemplo com os 5 cenarios
│   ├── security_alerts.json   # linha de base ficticia de logins por usuario
│   ├── detection_rules.json   # limiares configuraveis de deteccao
│   ├── mitre_attack.json      # base local de tecnicas MITRE ATT&CK
│   └── incident_examples.json # exemplos ilustrativos de incidentes
│
├── src/
│   ├── main.py                # interface grafica (Tkinter)
│   ├── log_analyzer.py        # parsing de logs
│   ├── alert_classifier.py    # deteccao, severidade e recomendacoes
│   ├── mitre.py                # consulta a base MITRE ATT&CK
│   └── incident_report.py     # geracao de relatorios de incidente
│
├── tests/
│   ├── conftest.py
│   ├── test_log_analyzer.py
│   ├── test_classifier.py
│   └── test_report.py
│
├── reports/                    # relatorios .json gerados em tempo de execucao
├── screenshots/                # capturas de tela da interface (opcional)
│
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

## Instalação

Pré-requisitos: **Python 3.10 ou superior**. O Tkinter já acompanha a
instalação padrão do Python na maioria dos sistemas (em algumas
distribuições Linux é necessário instalar o pacote `python3-tk`
separadamente, ex.: `sudo apt install python3-tk`).

```bash
# 1. Clonar o repositório
git clone https://github.com/<seu-usuario>/SOC-Analyst-Assistant.git
cd SOC-Analyst-Assistant

# 2. (Opcional, recomendado) Criar um ambiente virtual
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 3. Instalar as dependencias (apenas pytest, para os testes)
pip install -r requirements.txt
```

## Uso

Executar a interface gráfica:

```bash
python3 src/main.py
```

Fluxo na interface:

1. Clique em **"Selecionar arquivo de log"** e escolha um arquivo
   `.log` (o projeto já inclui `data/sample_auth.log` com os 5
   cenários de demonstração).
2. Clique em **"Executar análise"**.
3. A lista à esquerda mostra cada alerta detectado, com tipo,
   severidade, IP de origem e usuário afetado.
4. Selecione um alerta para ver, à direita, o relatório completo:
   evidência, justificativa da severidade, técnica MITRE ATT&CK e
   recomendações de investigação.
5. Clique em **"Gerar relatório (.json)"** para salvar o relatório
   selecionado na pasta `reports/`.

Também é possível usar os módulos diretamente em um script Python,
sem interface gráfica:

```python
import sys
sys.path.insert(0, "src")

import log_analyzer
import alert_classifier
import incident_report

events = log_analyzer.parse_log_file("data/sample_auth.log")
alerts = alert_classifier.run_all_detections(events)
reports = incident_report.build_reports_from_alerts(alerts)

for report in reports:
    print(incident_report.format_report_text(report))
```

## Exemplo de saída

```text
============================================================
SECURITY INCIDENT REPORT
============================================================

Incident ID: INC-001
Date: 2026-09-07 22:17:19

Type: Brute Force

Severity: HIGH
Justification: Volume de tentativas (12) e muito superior ao limiar
minimo (5), fortemente compativel com atividade de forca bruta
automatizada.

Source IP: 192.168.1.50
Affected User: admin

Evidence:
  12 tentativas de autenticacao falhas para o usuario 'admin' a
  partir do IP 192.168.1.50, entre 22:15:01 e 22:17:19.

Detection Rule: Multiplas tentativas de autenticacao falhas para o
mesmo usuario/origem dentro de uma janela de tempo curta.

MITRE ATT&CK:
  T1110 - Brute Force

Recommendations:
  - Verificar se houve autenticacao bem-sucedida apos as tentativas falhas.
  - Investigar a reputacao e o historico do IP de origem.
  - Verificar se outros usuarios foram alvo do mesmo IP de origem.
  - Avaliar bloqueio temporario ou rate limiting para a origem.
  - Revisar politica de bloqueio de conta apos multiplas falhas.

Status: UNDER INVESTIGATION
============================================================
```

## Testes

O projeto inclui testes automatizados com `pytest`, cobrindo o parser
de logs, cada regra de detecção, a classificação de severidade e a
geração de relatórios — sempre com dados simulados.

```bash
python3 -m pytest tests/ -v
```

Saída esperada: todos os testes (20) devem passar.

## Limitações

- Este é um projeto **educacional**: não substitui um SOC real, um
  SIEM, um EDR ou qualquer ferramenta de segurança em produção.
- As regras de detecção são simples e baseadas em limiares fixos
  (configuráveis em `data/detection_rules.json`), sem correlação
  estatística avançada, machine learning ou threat intelligence
  externa.
- Reconhece apenas dois formatos de log nesta V1 (autenticação SSH e
  bloqueios de firewall simulados).
- Não há persistência em banco de dados; os relatórios são salvos
  individualmente em arquivos `.json`.
- A ferramenta nunca executa ações ofensivas, de exploração ou de
  acesso não autorizado — apenas leitura e análise de dados fornecidos.

## Melhorias futuras

- Integração com APIs de Threat Intelligence (reputação de IP, feeds
  de IOCs).
- Suporte a mais formatos de log (Windows Event Log, Apache/Nginx,
  Cloud provedores).
- Dashboard com visão consolidada de todos os incidentes.
- Integração com um SIEM real.
- Persistência em banco de dados para histórico de incidentes.
- Cobertura de mais técnicas do MITRE ATT&CK.

## Autor

Desenvolvido por **Gabriel Wendel** como projeto de portfólio, no
contexto dos estudos em Defesa Cibernética.
