#!/usr/bin/env python3

import argparse
import csv
import re
import os

import gnupg

try:
    from config import CSV_FIELDS, FIELD_DEFAULTS, FIELD_FUNCTIONS, FIELD_PATTERNS, FIRSTLINE_IS_LOGIN_PASSWORD, FALLBACK_FIELD
except ImportError:
    from defaults import CSV_FIELDS, FIELD_DEFAULTS, FIELD_FUNCTIONS, FIELD_PATTERNS, FIRSTLINE_IS_LOGIN_PASSWORD, FALLBACK_FIELD

DOMAIN_REGEX_RAW = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
DOMAIN_REGEX = re.compile(DOMAIN_REGEX_RAW)

def traverse(directory):
    pass_files = []

    for root, dirs, files in os.walk(directory):
        if '.git' in dirs:
            dirs.remove('.git')

        for name in files:
            pass_files.append(os.path.join(root, name))

    return pass_files


def decrypt(files, binary, agent):
    gpg = gnupg.GPG(gpgbinary=binary,
                    use_agent=agent)
    gpg.encoding = 'utf-8'

    datas = []

    for path in files:
        file = os.path.splitext(path)[0]
        extension = os.path.splitext(path)[1]

        if extension == '.gpg':
            with open(path, 'rb') as gpg_file:
                decrypted = {
                    'path': file,
                    'data': str(gpg.decrypt_file(gpg_file))
                }

                datas.append(decrypted)

    return datas

def _guess_uri(row):
    if not 'login_uri' in row:
        return ''
    if re.search(DOMAIN_REGEX, row["name"]):
        return row["name"]
    return ''

def parse(base_dir, files):
    parsed = []

    for file in files:
        row = {}

        lines = file['data'].splitlines()

        # Note down which CSV_FIELDS have been found in the file
        found_fields = set()

        # Populate default and function-based fields
        for field in FIELD_DEFAULTS:
            row[field] = FIELD_DEFAULTS[field]

        for field in FIELD_FUNCTIONS:
            row[field] = FIELD_FUNCTIONS[field](base_dir, file['path'], file['data'])

        # Show warning if file is empty
        if not lines:
            print(f"Warning: File '{file['path']}' is empty.")
            parsed.append(row)
            continue

        # Treat first line as password if configured
        if FIRSTLINE_IS_LOGIN_PASSWORD and lines:
            row['login_password'] = lines[0]
            found_fields.add('login_password')
            lines = lines[1:]

        # Store all non-matching lines
        fallback_field_lines = []

        # Process other lines and extract fields based on patterns
        for line in lines:
            for field, pattern in FIELD_PATTERNS.items():
                match = re.match(pattern, line, re.I)
                if match:
                    # If the field was already found, print a warning and skip
                    if field in found_fields:
                        print(f"Warning: Duplicate field '{field}' found in file '{file['path']}'. Skipping duplicate.")
                        continue

                    row[field] = match.group(1)
                    found_fields.add(field)
                    break
            else:
                fallback_field_lines.append(line)
                if not FALLBACK_FIELD in found_fields:
                    found_fields.add(FALLBACK_FIELD)

        # Populate fallback field if any lines were stored
        if FALLBACK_FIELD in found_fields:
            row[FALLBACK_FIELD] = '\n'.join(fallback_field_lines)

        # Set all missing fields to empty string
        for field in CSV_FIELDS:
            if field not in row:
                row[field] = ''

        if row['login_uri'] == '':
            row['login_uri'] = _guess_uri(row)
        parsed.append(row)

    return parsed


def write(data, output_file):
    with open(output_file, 'w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)

        writer.writeheader()

        for row in data:
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(description='Export password-store data to Bitwarden CSV format.')

    parser.add_argument('--directory', '-d', default='~/.password-store',
                        help='Directory of the password store.')
    parser.add_argument('--gpg-binary', '-b', dest='binary', default='/usr/bin/gpg',
                        help='Path to the GPG binary.')
    parser.add_argument('--output-file', '-o', dest='output', default='pass.csv',
                        help='File to write the CSV in.')
    parser.add_argument('--gpg-agent', '-a', dest='agent', help='Use GPG agent.', action='store_true')

    args = parser.parse_args()

    password_store = os.path.expanduser(args.directory)

    encrypted_files = traverse(password_store)

    decrypted_files = decrypt(encrypted_files, args.binary, args.agent)

    csv_data = parse(password_store, decrypted_files)

    write(csv_data, args.output)


if __name__ == '__main__':
    main()
