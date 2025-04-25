import re

# Lista de exemplos de endereços (BTC, ETH, etc.)
wallet_samples = [
    "bc1q4g636c8qlqpazkxc73zeudsn4e52mysycfmfwm",  # BTC
    "0x4FB2b1d8092f68cBcBd731Df2781B2A8E5d2cBfA",  # ETH
    "bc1q4g636c8qlqpazkxc73zeudsn4e52mysycfmfwm",  # BTC bech32
    "no_wallet_here",
]

# Regex simples para carteiras
wallet_patterns = {
    "BTC": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"),
    "ETH": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
}

def detect_wallets(text):
    found = []
    for wallet_type, pattern in wallet_patterns.items():
        matches = pattern.findall(text)
        if matches:
            found.append((wallet_type, matches))
    return found

if __name__ == "__main__":
    for sample in wallet_samples:
        detected = detect_wallets(sample)
        if detected:
            print(f"[+] Detectado: {detected}")
        else:
            print(f"[-] Nenhuma wallet detectada em: {sample}")
