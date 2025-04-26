# 🧠 Browser Attack Module — RansomLab-Pro

> **⚠️ AVISO LEGAL:** Este módulo é parte de um framework educacional de simulação ofensiva. Seu uso deve ocorrer **exclusivamente em ambientes controlados**, com fins de **pesquisa, defesa e estudo**. Qualquer uso indevido é de total responsabilidade do executor.

---

## ✨ Visão Geral

O módulo `bowsers-attack` é um sistema completo de extração de credenciais sensíveis armazenadas em navegadores web, como:

- Google Chrome
- Microsoft Edge
- Brave Browser

> 🤓 Através da descriptografia local (usando DPAPI), o módulo simula o comportamento de stealers como **RedLine**, **Racoon** e variantes de **APT** focadas em coleta de credenciais e cookies.

---

## ⚖️ Finalidade do Módulo

Este componente foca em **navegadores web**, com os seguintes objetivos:

| Tipo de Dado          | Finalidade                                |
|-----------------------|-------------------------------------------|
| Credenciais salvas    | Logins e senhas de plataformas críticas  |
| Cookies               | Roubo de sessão, bypass de autenticação  |
| Tokens Web            | Potencial hijack de sessão               |
| Perfis Web            | Rastreamento e fingerprinting             |

---

## ⚡ Mecanismo Interno

1. **Localiza perfis de navegador via variáveis de ambiente**
2. **Obtém a chave-mestra criptografada (DPAPI)**
3. **Descriptografa a chave com win32crypt**
4. **Abre bancos SQLite dos navegadores**
5. **Descriptografa campos de senhas/cookies criptografados (AES)**
6. **Exporta tudo para arquivos estruturados**

> Os formatos dos dumps podem ser `.txt`, `.json` ou qualquer outro, dependendo do submódulo utilizado.

---

## 🔧 Componentes Internos

```bash
bowsers-attack/
├── browser_dump.py         # Dump de credenciais + cookies
├── redline_clone.py        # Dump JSON estilo RedLine Stealer
├── stealers_controller.py  # Controlador geral
├── output/                 # Arquivos extraídos
└── tmp_*.db                # Dbs temporários clonados
```

### 🧰 `browser_dump.py`
- Extração detalhada com interface Rich
- Mostra prévia de credenciais e cookies em tabelas

### 💎 `redline_clone.py`
- Emula o comportamento de malware como RedLine
- Exporta para JSON padronizado para análise futura

### 🔹 `stealers_controller.py`
- Executa ambos scripts
- Ideal para integração com loaders ou backdoors

---

## 💡 Como Executar

> Recomendado: Ambiente virtual com Python 3.10+ no Windows (com navegadores instalados)

```bash
git clone https://github.com/seuusuario/RansomLab-Pro.git
cd RansomLab-Pro/bowsers-attack
python stealers_controller.py
```

Saída esperada:
- `browser_dumps_<timestamp>/` com arquivos de credenciais e cookies
- `output/redline_cred_dump.json` com estrutura tipo malware

---

## 🔫 Cenário de Uso Simulado (Laboratório)

```plaintext
Usuário executa payload
⬇️
Script stealth coleta dados do navegador
⬇️
Dump salvo localmente ou enviado para servidor
⬇️
Atacante coleta senhas, acessa recursos e move-se lateralmente
```

---

## 🚫 Restrições

- ❌ Apenas para estudo
- ❌ Não usar em redes reais sem autorização
- ⚡ Não substitui antivírus ou EDR

---


stealth_launcher/
├── advanced/
│   ├── hooking.py
│   ├── reflective_loader.py
│   └── syscall_stubs.py
├── stages/
│   ├── beaconing.py
│   ├── cleanup.py
│   ├── evasion.py
│   ├── mutex.py
│   ├── patching.py
│   ├── payload_execution.py
│   ├── payload_integrity.py
│   └── persistence.py
├── config.py
├── exceptions.py
├── logger.py
├── orchestrator.py
├── README.md
└── stealth_launcher.py








Segue a análise detalhada, arquivo a arquivo, das técnicas e responsabilidades de cada módulo:

patching.py

Aplica patches diretos em funções de DLLs para desativar mecanismos de tracing e antivírus:

ETW/WPP: sobrescreve EtwEventWrite e EtwEventWriteEx em ntdll.dll e kernel32.dll com instruções que retornam imediatamente.

AMSI: remove hooks de AmsiScanBuffer e AmsiGetResult em amsi.dll com patch que sempre retorna sucesso.

Callbacks de kernel: usa NtSetSystemInformation para desativar callbacks de tracing do kernel.

Anti-AV: desativa o serviço Windows Defender via sc e ajusta registro para remover tamper protection.

Network camouflage: altera chaves de proxy/registry em WinSock para criptografar tráfego e ocultar padrões.

Anti-debug: instala vectored exception handler para ignorar STATUS_BREAKPOINT e desabilita flags de debug do processo via NtSetInformationProcess.

Rootkit driver: copia driver malicioso para System32\drivers, cria e inicia serviço de kernel para persistência stealth.

Orquestra tudo em patch_etw_stage, lançando PatchError em caso de falhas ​
.

payload_execution.py

Classe PayloadExecutor gerencia o ciclo de vida do payload:

Verificação de assinatura: confere hash se fornecido.

Empacotamento/ofuscação: utiliza pack_payload para gerar executável ofuscado.

Evasão dinâmica: executa testes de hypervisor, sandbox e fingerprint de hardware.

Integridade: chama self_integrity_check para checar hash e watermark.

Injeções avançadas: tenta múltiplas técnicas (Early-Bird, Kernel-Assisted Reflective Loader, Process Doppelgänging, Dynamic Syscall, Ghost APC, Hop-Scotch) com fallback para executável temporário via cópia em %TEMP%.

Comunicação e exfiltração: inicia communication_exfiltration_stage.

Persistência: chama persistence_stage.

Autolimpeza: finaliza com cleanup_stage.

Trampa falhas de cada técnica com logs e PackingError/StageError ​
.

payload_integrity.py

Garante que o payload não foi alterado indevidamente antes da injeção:

compute_file_hash: lê o arquivo em blocos e calcula SHA-256 (ou outro algoritmo).

verify_memory_integrity: mapeia em memória e compara hash com esperado.

check_watermark: busca uma sequência de 4 bytes (WATERMARK_KEY) como honeypot.

self_integrity_check: orquestra hash + watermark, lançando StageError em caso de inconsistência. ​
.

persistence.py

Implementa várias técnicas de persistência de alto nível:

UEFI NV Variable: usa efivars.exe para escrever variáveis no firmware (se disponível).

COM Hijack: altera chave HKLM\SOFTWARE\Classes\CLSID\{...}\InprocServer32 via reg.exe para carregar DLL maliciosa.

WMI Event Subscription: registra evento WMI que dispara script sempre que um processo é criado.

Firmware Bootkit: utiliza dd para escrever primeiro setor de disco (/dev/sda), instalando bootkit.

Rollback: remove UEFI var, desfaz COM hijack e cancela WMI event.

Verifica privilégios de administrador antes de cada etapa e registra falhas sem abortar todo o processo ​
.

beaconing.py

Estratégias de beaconing C2 furtivas e resilientes:

HTTP/2 multiplexado sobre TLS, com headers camuflados e payloads cifrados via AES-GCM.

DNS-over-HTTPS (consultas TXT encadeadas) como fallback.

Malha P2P (UDP) criptografada com AES-GCM para peers configurados.

Túnel ICMP em pacotes Echo Request com payload fragmentado.

Introduz jitter aleatório, seleciona técnica de evasão (API hooking, syscall hooking, obfuscação) antes de enviar beacon.

Orquestra em beaconing_stage, iterando endpoints e fallbacks, e lança BeaconingError se todas falharem ​
.

cleanup.py

Limpeza pós-execução e suporte a manutenção do “ataque”:

Remove arquivos de logs e temporários (/tmp e logs/beaconing.log).

Fecha sockets abertos e mata processos relacionados (beaconing_stage) via psutil.

Limpa cache DNS e histórico de comandos do shell.

Remove módulos Python carregados de stealth_launcher.

Inicia threads de ataque simultâneas e uma thread de cleanup dedicada, aguardando todas finalizarem. ​
.

evasion.py

Conjunto de técnicas de evasão de ambiente e anti-análise:

Geração de stubs em memória para instrução CPUID e chamadas de syscalls customizadas.

Timing attacks (acesso a \\.\PhysicalDrive0 e QueryPerformanceCounter) para detectar VMs.

Análise de token de processo para detectar depuradores.

Handlers de exceção para filtrar STATUS_BREAKPOINT.

Funções de monitoramento de EDRs via NtQuerySystemInformation.

Testes de sandbox via DNS-over-HTTPS ou DnsQueryEx.

Ocultação de processos/threads com NtSetInformationProcess/Thread.

Orquestra em evasion_stage, abortando em falhas críticas e continuando em checks não-críticos ​
.

mutex.py

Garante instância única (single-instance) combinando dez técnicas distintas:

Win32 CreateMutexW

Syscall NtCreateMutant

Win32 CreateEventW

Syscall NtCreateEvent

Win32 CreateSemaphoreW

Syscall NtCreateSemaphore

Syscall NtCreateSection

Syscall GlobalAddAtom

Named Pipe via syscall

File lock em %TEMP%

Implementa MultiTechniqueMutex com acquire() testando cada método em sequência e release() limpando todos os handles e arquivos de lock. Oferece acquire_mutex e release_mutex como wrappers 

syscall_stubs.py

Fornece wrappers para invocar diretamente syscalls do Windows (funções Nt*) via ctypes, sem passar pelas APIs de alto nível da Win32.

Técnicas: montagem manual de estruturas como UNICODE_STRING e OBJECT_ATTRIBUTES; chamadas a NtCreateMutant (para mutexes), NtClose, NtOpenProcess, NtCreateSection + NtMapViewOfSection, NtWriteVirtualMemory e NtCreateThreadEx.

Uso principal: criar mutexes, abrir processos, mapear e escrever seções de memória e criar threads remotas de forma “não convencional” (evitando APIs detectáveis) .

hooking.py

Implementa inline hooks e syscall hooks em memória: altera o fluxo de execução de funções exportadas ou chamadas de syscalls.

Técnicas de inline-hook: localiza o endereço de uma função exportada, altera proteções de página para RWX, insere um jump curto (trampoline) para código customizado e restaura bytes originais ao remover o hook.

Técnicas de syscall-hook: gera stubs em memória que modificam dinamicamente o número de syscall e atualiza uma tabela inline JIT de syscalls; inclui funções para desfazer todos os hooks antes do cleanup .

reflective_loader.py

Carrega binários PE (Portable Executable) “em memória” no processo alvo, sem usar chamadas padrão de carregamento de módulos.

Técnicas: leitura do arquivo PE em buffer, parsing de DOS_HEADER, NT_HEADERS e SECTION_HEADERS; alocação de memória remota (VirtualAllocEx), cópia de seções, aplicação de relocations e resolução manual de importações; criação de thread remota (via NtCreateThreadEx) apontando para o entrypoint refletivo .

exceptions.py

Define hierarquia de exceções customizadas para cada “estágio” da execução (evasion, patching, packing, stealer, beaconing, persistence, cleanup).

Técnicas: cada erro armazena timestamp, stack trace (excluindo frames internos), PID, host e código de erro via enum.IntEnum; sobrescreve __str__ para formatar mensagem com contexto e causa original ​
.

logger.py

Configura sistema de logging avançado para registro local e exfiltração.

Técnicas:

JSONFormatter: formatação de logs em JSON, incluindo timestamp, nível, estágio, módulo, função, PID e hostname.

RotatingFileHandler: gravação em arquivo com rotação baseada em tamanho.

RingBufferHandler: buffer em memória (thread-safe) para retenção de últimas N mensagens.

C2LogHandler: enfileiramento e envio assíncrono de logs críticos via UDP para endpoints configuráveis (exfiltração).

Adiciona opcionalmente handler de console em modo verbose ​
.

orchestrator.py

Coordena toda a execução do “Stealth Launcher” em fases bem definidas.

Técnicas e fluxo:

Verifica SO e privilégios de administrador (NT).

Carrega configuração e inicializa logging.

Garante execução única via mutex.

Inicia timer global para abortar após tempo máximo.

Itera sobre estágios (evasion, patching, payload_execution, beaconing, persistence), executando cada função e tratando falhas (com retry parcial ou abort normal).

Envio opcional de health beacon.

Cleanup final: cancela timer, executa etapa de limpeza de recursos e libera mutex.

Conecta os módulos de exceptions, logger, config e as implantações dos estágios em stealth_launcher.stages.* ​
.

config.py

Carrega e valida parâmetros de configuração a partir de arquivo YAML ou variáveis de ambiente; provê valores default robustos.

Técnicas:

Uso de pathlib.Path para resolver log_file e payload_path.

Parsing de tipos (int, bool, list) com fallback em defaults.

Garante obrigatoriedade de PAYLOAD_PATH, lançando FileNotFoundError se ausente.

Estrutura de dados unificada via classe Config contendo mutex, C2 endpoints, thresholds de latência e ações humanas, flags de ofuscação etc. ​
.


