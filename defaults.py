import os

# https://help.bitwarden.com/article/import-data/#generic-csv-format-individual-account
CSV_FIELDS = [
    'name',
    'folder',
    'type',
    'favorite',
    'notes',
    'fields',
    'login_totp',
    'login_uri',
    'login_username',
    'login_password'
]

FIELD_DEFAULTS = {
    'type': 'login'
}

FIELD_FUNCTIONS = {
    'name': lambda base, path, data: os.path.basename(path),
    'folder': lambda base, path, data: os.path.dirname(path).replace(base, '').lstrip('/'),
}

FIELD_PATTERNS = {
    'login_uri': '^url ?: ?(.*)$',
    'login_username': '^(?:user|login|username).* ?: ?(.*)$',
    'login_totp': r'otpauth://totp/[^?]+\?secret=([^&]+)',
}

FALLBACK_FIELD = 'notes'

FIRSTLINE_IS_LOGIN_PASSWORD = True