import locale

def detect_locale():
    loc = locale.getdefaultlocale()
    return loc[0] if loc else 'en-US'
