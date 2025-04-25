# 💀 PhantomAI-Pro — Offensive Cyber Threat Simulation Framework

> **⚠️ PROJETO EDUCACIONAL E DE PESQUISA**
>  
> Este laboratório foi desenvolvido **exclusivamente para fins de estudo, simulação controlada e defesa cibernética avançada**. Nenhuma parte deste projeto deve ser usada fora de ambientes privados e éticos.  
>  
> 🔐 Use com responsabilidade. Você é o único responsável pelas consequências de sua execução.

---

## ⚙️ Visão Geral

O **RansomLab-Pro** é um framework avançado e modular para **simular técnicas reais de ataque cibernético**, com foco em ransomware, info-stealers, engenharia social, RATs, supply chain, evasão forense, malware Android e IA ofensiva.

Inspirado nas ameaças **mais modernas usadas por grupos como LockBit, Lazarus, ALPHV, APT28, EvilCorp, Scattered Spider**, este projeto permite:
- Estudo técnico detalhado das técnicas atuais e futuras
- Testes de defesa em ambientes controlados
- Análise forense de vetores reais
- Criação de contra-medidas baseadas em ameaças reais

> 🧠 Inclui integração com **IA ofensiva**, simulação de APTs, engenharia social com deepfakes, criptografia real (AES+RSA), gerador de ransom notes, malware Android, RATs, MFA bypass, supply chain backdoors, wallet stealers e muito mais.

---

## 🧬 Estrutura Modular (v1.5)

```bash
RansomLab-Pro/
├── core/                      # Criptografia AES+RSA, stealth, compressão
│   ├── encryptor.py
│   ├── decryptor.py
│   └── compression.py

├── evasion/                  # Anti-VM, Anti-Debug, Anti-Sandbox
│   ├── evasion_controller.py
│   └── detectors/

├── ransom/                   # Note Generator, fake Defender, HUD popup
│   ├── ransom_note_generator.py
│   ├── auto_popup_stager.py
│   └── fullscreen_fake_defender.py

├── android/                  # APK builders maliciosos e coleta Android
│   ├── brasdex_simulator.py
│   └── apk_builder.py

├── stealers/                 # RedLine, Clipper, browser dump, wallet stealers
│   ├── redline_clone.py
│   ├── clipper.py
│   └── browser_dump.py

├── rat/                      # Keylogger, RAT (Async/Quasar), persistência
│   ├── keylogger.py
│   ├── rat_module.py
│   └── persistence.py

├── phishing/                 # Deepfake voice, e-mail phishing com LLM
│   ├── email_generator_llm.py
│   ├── deepvoice_sim.py
│   └── fake_login_pages/

├── mfa_bypass/               # EvilProxy, token sniffers, session hijack
│   ├── evilproxy_simulator.py
│   └── token_sniffer.py

├── supply_chain/             # Backdoors em PyPI, GitHub, Dockerfile
│   ├── pypi_backdoor_injector.py
│   ├── dockerfile_injector.py
│   └── github_payloads/

├── apt_campaigns/            # Simulação de APTs (APT28, Lazarus, Volt Typhoon)
│   ├── apt28_sim.py
│   ├── volt_typhoon_tools.py
│   └── infrastructure_mapping/

├── ai_modules/               # IA ofensiva: polimorfismo, LLM abuse, model poisoning
│   ├── polymorphic_generator.py
│   ├── model_poisoner.py
│   └── llm_attack_tester.py

├── builder/                  # Keygen, build config, infectors
│   ├── config.py
│   ├── keygen.py
│   └── build_profile.json

├── output/                   # Arquivos infectados, logs, registros
│   └── ...

├── forensic/                 # Ferramentas de análise reversa e recuperação
│   └── ...

├── decryptor_tools/          # Ferramentas reversas e interfaces GUI
│   └── ...

├── lab-snapshots/            # Imagens de máquinas, dumps, ambientes infectados
│   └── ...

├── scripts/                  # Helpers, execução de payloads, auto deploy
├── main.py                   # Entrada principal para testes e simulação
└── run_demo.py               # Execução de cadeia completa (infection chain)

🧠 Módulos Estratégicos (Prontos para Estudo e Defesa)

Módulo	Descrição	Técnica
core/	Criptografia AES+RSA + compressão	Simula LockBit, ALPHV
evasion/	Anti-VM, Anti-Debug, sandbox check	Bypass AV e EDR
ransom/	HUD fake Defender + popup forçado + note	Engenharia visual
stealers/	Clipper, RedLine clone, browser dump	Roubo de credenciais
rat/	Async RAT + keylogger real	Controle remoto e espionagem
android/	BrasDex, APK collector, payloads fake	Malware mobile
phishing/	LLM para gerar iscas personalizadas	Engenharia social IA
mfa_bypass/	EvilProxy + token hijack	MFA Stealing
supply_chain/	Injeção em PyPI, GitHub, Docker	Ataque em massa via cadeia
apt_campaigns/	Lazarus, APT28, Volt Typhoon (simulado)	Ciberespionagem
ai_modules/	Polimorfismo, model poisoning, payloads IA	Malware adaptativo

🔥 Exemplos Reais Simulados

💣 MOVEit Supply Chain Attack (supply_chain/)

🧠 Deepfake de CEO (phishing/deepvoice_sim.py)

🔓 Spoofing Cripto com clipboard hijack (stealers/clipper.py)

🖥️ BlackCat + LockBit Ransom HUD (ransom/fullscreen_fake_defender.py)

📲 BrasDex e malware Android (android/)

🧪 Lazarus Crypto Theft Simulation (apt_campaigns/)

💻 Requisitos Técnicos
Python 3.10+

Ambiente virtual recomendado (venv)

Executar em máquina virtual ou sandbox isolado ⚠️

Opções:

Linux / Windows (VMware, VirtualBox)

Android Emulator (para android/)

🚀 Como Executar (Modo Laboratório)

git clone https://github.com/seuusuario/RansomLab-Pro.git
cd RansomLab-Pro
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run_demo.py
🧪 Foco Principal: Simulação e Defesa
✅ Simular: Comportamento de ransomwares, stealers, RATs reais
✅ Estudar: Como os ataques acontecem e como defender
✅ Construir: Contra-medidas técnicas e táticas de mitigação
✅ Monitorar: Logs, mutações, antiforenses
✅ Preparar: Equipes de segurança para ataques reais

🧠 Futuras Fases (Planejamento Avançado)
🌐 Dashboard HUD IA para simular vítima

🧬 Modelo de IA treinado para evasão e adaptação (auto-malware)

🔐 Integração com honeypot interativo

🕵️ Ferramentas de Threat Hunting + análise forense real

🦠 Simulação de malware fileless (PowerShell, LOLBins)

🤖 Orquestração com scripts bash/PowerShell + Cobalt Strike simulado

🔐 Propósito Educacional
Este projeto NÃO é um malware funcional para uso ofensivo fora de ambientes de laboratório. Todas as simulações devem ser conduzidas de forma segura, isolada e ética, com objetivo único de estudo, hardening e resposta a incidentes.

📚 Fontes e Base Técnica
CrowdStrike Global Threat Report

Kaspersky APT Reports

Fortinet Threat Intelligence

CheckPoint Research

Mandiant M-Trends

IBM X-Force Threat Intelligence

Relatório interno: Crimes Cibernéticos Avançados 2023–2025

👤 Autor
Paulo [Oficial] — Offensive Security Researcher & Developer
🧠 Especialista em: IA aplicada à segurança, engenharia reversa, simulações forenses

⚠️ Aviso Legal
Este projeto foi criado para fins de educação, pesquisa forense e segurança ofensiva controlada. É estritamente proibido executar ou adaptar este código para finalidades ilícitas.

Todos os testes devem ser realizados exclusivamente em ambientes próprios, privados e isolados (VMs, air-gap, sandbox). Qualquer uso indevido é de total responsabilidade do executor.

📡 SIGA DESENVOLVIMENTO: Versão v1.5 em produção de testes. IA ofensiva e simulações APT/Android em andamento. Contribuições futuras e colaborações em segurança são bem-vindas.

yaml
