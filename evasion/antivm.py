import platform
import subprocess
import os

def check_virtual_environment() -> bool:
    """
    Detecta se o ambiente está rodando em uma VM comum como VirtualBox, VMware ou Hyper-V.
    Retorna True se uma VM for detectada.
    """
    indicators = []

    try:
        system = platform.system()

        if system == "Windows":
            output = subprocess.check_output("wmic baseboard get manufacturer,product", shell=True)
            output = output.decode().lower()

            vm_keywords = ["virtualbox", "vmware", "qemu", "xen", "bochs", "parallels", "kvm"]
            for word in vm_keywords:
                if word in output:
                    indicators.append(word)

            # Detecta drivers típicos de VM
            drivers = ["VBoxMouse", "VBoxGuest", "VBoxSF", "vmmouse", "vmhgfs", "vm3dgl", "vmrawdsk"]
            for driver in drivers:
                try:
                    subprocess.check_output(f"sc query {driver}", shell=True)
                    indicators.append(driver)
                except:
                    pass

    except Exception as e:
        print(f"[!] Erro ao verificar VM: {e}")

    if indicators:
        print(f"[⚠️] Ambiente virtual detectado: {', '.join(indicators)}")
        return True
    else:
        print("[✔️] Nenhum sinal de ambiente virtual encontrado.")
        return False
