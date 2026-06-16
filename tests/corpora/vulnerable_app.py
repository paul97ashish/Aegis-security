"""Seeded-bug fixture for evals (design §13 eval harness).

Hand-planted CWEs with expectations encoded in EXPECTED_CWES. Used to measure
precision/recall and PoC-confirmation rate per model config. This file is NOT
meant to run — it is a scanner target.
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests

# Expected findings (CWE ids) the pipeline should surface in this file.
EXPECTED_CWES = {
    "CWE-89",   # SQL injection
    "CWE-78",   # command injection
    "CWE-502",  # unsafe deserialization
    "CWE-798",  # hardcoded secret
    "CWE-327",  # weak hash
    "CWE-330",  # insecure RNG
    "CWE-94",   # eval
    "CWE-918",  # SSRF
}

API_KEY = "sk_live_abcd1234efgh5678ijkl"  # CWE-798 hardcoded secret


def get_user(db: sqlite3.Connection, user_id):
    cur = db.cursor()
    # CWE-89: string-formatted SQL
    cur.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
    return cur.fetchone()


def ping(host):
    # CWE-78: shell command injection
    return os.system("ping -c 1 " + host)


def run(cmd):
    # CWE-78: subprocess with shell=True
    return subprocess.run(cmd, shell=True)


def load_blob(data):
    # CWE-502: unsafe deserialization
    return pickle.loads(data)


def token():
    # CWE-330: insecure RNG for a token
    return random.randint(0, 999999)


def digest(password):
    # CWE-327: weak hash
    return hashlib.md5(password.encode()).hexdigest()


def calc(expr):
    # CWE-94: dynamic code execution
    return eval(expr)


def fetch(url_part):
    # CWE-918: SSRF via dynamic URL
    return requests.get("http://" + url_part)
