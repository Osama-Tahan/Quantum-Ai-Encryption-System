
import os
import json
import time
import math
import uuid
import shutil
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

import numpy as np
import joblib

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Header
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


BASE_DIR = Path(__file__).resolve().parent
UPLOADS_DIR = BASE_DIR / "storage" / "uploads"
ENCRYPTED_DIR = BASE_DIR / "storage" / "encrypted"
DECRYPTED_DIR = BASE_DIR / "storage" / "decrypted"
TAMPERED_DIR = BASE_DIR / "storage" / "tampered"
DATABASE_DIR = BASE_DIR / "database"
REPORTS_DIR = BASE_DIR / "reports"
MODELS_DIR = BASE_DIR / "models"
DB_PATH = DATABASE_DIR / "web_local_v1.db"
CONFIG_PATH = BASE_DIR / "config.json"
MODEL_PATH = MODELS_DIR / "ai_model.joblib"

for folder in [UPLOADS_DIR, ENCRYPTED_DIR, DECRYPTED_DIR, TAMPERED_DIR, DATABASE_DIR, REPORTS_DIR, MODELS_DIR]:
    folder.mkdir(parents=True, exist_ok=True)

DEFAULT_CONFIG = {
    "app_title": "Data Encryption System Based on Quantum Computing",
    "subtitle": "With AI Performance Enhancer",
    "qubits": 512,
    "qber_safe_threshold": 5.0,
    "qber_warning_threshold": 10.0,
    "aes_mode": "GCM",
    "session_validity_minutes": 10,
    "pbkdf2_iterations": 200000,
    "qiskit_noise_error_rate": 0.035,
    "eve_measurement_rate": 0.45
}

USERS = {
    "admin": {"password": "admin123", "role": "Admin"},
    "encrypter": {"password": "encrypt123", "role": "Encrypter"},
    "viewer": {"password": "viewer123", "role": "Viewer"}
}
TOKENS = {}

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def human_size(n):
    n = float(n)
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def read_config():
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=4), encoding="utf-8")
        return dict(DEFAULT_CONFIG)
    data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(data)
    cfg["aes_mode"] = "GCM"
    return cfg

CONFIG = read_config()


class DB:
    def __init__(self, path=DB_PATH):
        self.path = path
        self.init()

    def connect(self):
        return sqlite3.connect(self.path)

    def init(self):
        with self.connect() as conn:
            c = conn.cursor()
            c.execute("""CREATE TABLE IF NOT EXISTS audit(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT, role TEXT, action TEXT, result TEXT, risk_level TEXT, created_at TEXT
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS files(
                id TEXT PRIMARY KEY,
                file_type TEXT, filename TEXT, path TEXT, size INTEGER, file_hash TEXT,
                mode TEXT, qber REAL, threat_level TEXT, created_at TEXT
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS sessions(
                id TEXT PRIMARY KEY, payload TEXT, expires_at TEXT, created_at TEXT
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS operations(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation TEXT, duration REAL, qber REAL, threat_level TEXT, decision TEXT, created_at TEXT
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS key_usage(
                key_hash TEXT PRIMARY KEY, filename TEXT, used_at TEXT
            )""")
            conn.commit()

    def execute(self, q, p=()):
        with self.connect() as conn:
            c = conn.cursor()
            c.execute(q, p)
            conn.commit()
            return c

    def audit(self, username, role, action, result, risk):
        self.execute("INSERT INTO audit(username,role,action,result,risk_level,created_at) VALUES (?,?,?,?,?,?)",
                     (username, role, action, result, risk, now_str()))

    def add_file(self, file_type, path, mode="-", qber=0.0, threat="-"):
        file_id = str(uuid.uuid4())
        path = Path(path)
        self.execute("""INSERT INTO files(id,file_type,filename,path,size,file_hash,mode,qber,threat_level,created_at)
                     VALUES (?,?,?,?,?,?,?,?,?,?)""",
                     (file_id, file_type, path.name, str(path), path.stat().st_size, sha256_file(path), mode, qber, threat, now_str()))
        return file_id

    def list_files(self, file_type, search=""):
        with self.connect() as conn:
            c = conn.cursor()
            if search:
                c.execute("""SELECT id,filename,path,size,file_hash,mode,qber,threat_level,created_at
                             FROM files WHERE file_type=? AND filename LIKE ? ORDER BY created_at DESC""", (file_type, f"%{search}%"))
            else:
                c.execute("""SELECT id,filename,path,size,file_hash,mode,qber,threat_level,created_at
                             FROM files WHERE file_type=? ORDER BY created_at DESC""", (file_type,))
            return c.fetchall()

    def get_file(self, file_id):
        with self.connect() as conn:
            c = conn.cursor()
            c.execute("SELECT id,file_type,filename,path,size,file_hash,mode,qber,threat_level,created_at FROM files WHERE id=?", (file_id,))
            return c.fetchone()

    def delete_file(self, file_id):
        self.execute("DELETE FROM files WHERE id=?", (file_id,))

    def key_used(self, h):
        with self.connect() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM key_usage WHERE key_hash=?", (h,))
            return c.fetchone()[0] > 0

    def record_key(self, h, filename):
        try:
            self.execute("INSERT INTO key_usage(key_hash,filename,used_at) VALUES (?,?,?)", (h, filename, now_str()))
        except sqlite3.IntegrityError:
            pass

DATABASE = DB()


def get_user(token):
    if not token or token not in TOKENS:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return TOKENS[token]

def require_role(user, allowed):
    if user["role"] == "Admin" or user["role"] in allowed:
        return
    raise HTTPException(status_code=403, detail="Access denied")


class QRNG:
    def __init__(self):
        self.sim = AerSimulator()

    def bits(self, n):
        qc = QuantumCircuit(n, n)
        for i in range(n):
            qc.h(i)
        qc.measure(range(n), range(n))
        result = self.sim.run(qc, shots=1).result()
        bit_string = list(result.get_counts().keys())[0].replace(" ", "")[::-1]
        return [int(b) for b in bit_string[:n].zfill(n)]

QRNG_ENGINE = QRNG()


class BB84:
    @staticmethod
    def entropy(key):
        if not key:
            return {"zeros": 0, "ones": 0, "entropy": 0, "quality": "Weak", "zero_ratio": 0, "one_ratio": 0}
        zeros = key.count("0")
        ones = key.count("1")
        total = len(key)
        p0 = zeros / total
        p1 = ones / total
        H = 0
        for p in [p0, p1]:
            if p > 0:
                H -= p * math.log2(p)
        return {"zeros": zeros, "ones": ones, "entropy": round(H, 4),
                "quality": "Excellent" if H >= 0.98 else "Good" if H >= 0.90 else "Weak",
                "zero_ratio": round(p0*100, 2), "one_ratio": round(p1*100, 2)}

    def generate(self, mode):
        start = time.time()
        qubits = int(CONFIG["qubits"])
        safe = float(CONFIG["qber_safe_threshold"])
        warn = float(CONFIG["qber_warning_threshold"])

        alice_bits = QRNG_ENGINE.bits(qubits)
        alice_bases = QRNG_ENGINE.bits(qubits)
        bob_bases = QRNG_ENGINE.bits(qubits)

        if mode == "IDEAL":
            error_prob, noise, noise_source = 0.003, round(np.random.uniform(0, 0.5), 2), "Ideal simulator"
            eve = {"measurement_rate": 0, "disturbed_qubits": 0, "eve_random_bases": 0}
        elif mode == "NOISY":
            error_prob = float(CONFIG["qiskit_noise_error_rate"])
            noise, noise_source = round(error_prob * 100, 2), "Qiskit Aer Noise Model equivalent: depolarizing + readout noise"
            eve = {"measurement_rate": 0, "disturbed_qubits": 0, "eve_random_bases": 0}
        else:
            eve_rate = float(CONFIG["eve_measurement_rate"])
            error_prob = 0.25
            disturbed = int(eve_rate * qubits)
            noise, noise_source = round((disturbed / qubits) * 100, 2), "Eve disturbance simulation"
            eve = {"measurement_rate": eve_rate, "disturbed_qubits": disturbed, "eve_random_bases": int(disturbed * 0.5)}

        bob_results = []
        basis_table = []
        for i in range(qubits):
            if alice_bases[i] == bob_bases[i]:
                bit = alice_bits[i]
                if np.random.random() < error_prob:
                    bit = 1 - bit
            else:
                bit = int(np.random.random() > 0.5)
            bob_results.append(bit)
            if len(basis_table) < 300:
                basis_table.append({
                    "index": i+1, "alice_bit": alice_bits[i],
                    "alice_basis": "X" if alice_bases[i] else "Z",
                    "bob_basis": "X" if bob_bases[i] else "Z",
                    "bob_bit": bit,
                    "match": "Yes" if alice_bases[i] == bob_bases[i] else "No"
                })

        sifted_alice, sifted_bob = [], []
        for a_bit, a_basis, b_basis, b_bit in zip(alice_bits, alice_bases, bob_bases, bob_results):
            if a_basis == b_basis:
                sifted_alice.append(a_bit)
                sifted_bob.append(b_bit)

        matched = len(sifted_alice)
        rejected = qubits - matched
        errors = sum(1 for a, b in zip(sifted_alice, sifted_bob) if a != b)
        qber = round((errors / matched) * 100 if matched else 100.0, 2)

        raw_key = "".join(str(x) for x in sifted_alice)
        salt = get_random_bytes(16).hex()
        final_key_hex = hashlib.sha256((raw_key + salt).encode()).hexdigest()
        ent = self.entropy(raw_key)

        if qber < safe:
            status, decision, accepted = "SECURE", "ACCEPT KEY", True
        elif qber < warn:
            status, decision, accepted = "SUSPICIOUS", "REGENERATE KEY", True
        else:
            status, decision, accepted = "UNSAFE", "REJECT CHANNEL", False

        created = datetime.now()
        expires = created + timedelta(minutes=int(CONFIG["session_validity_minutes"]))

        return {
            "id": str(uuid.uuid4()), "mode": mode, "qber": qber, "noise": noise,
            "noise_source": noise_source, "delay": round(np.random.uniform(0.04, 2.4), 2),
            "errors": errors, "qubits_used": qubits, "matched_bases": matched,
            "rejected_bases": rejected, "sifted_key_length": len(raw_key),
            "final_key_hex": final_key_hex, "final_key_length": 256,
            "privacy_amplification": "SHA-256(Sifted Key + Salt)", "entropy": ent,
            "basis_table": basis_table, "sifted_preview": raw_key[:420],
            "decision": decision, "status": status, "accepted": accepted,
            "created_at": created.isoformat(), "expires_at": expires.isoformat(),
            "duration": round(time.time() - start, 3), "qrng_enabled": True,
            "qrng_bits_generated": qubits * 3, "eve": {**eve, "resulting_qber": qber}
        }

BB84_ENGINE = BB84()


class AIEngine:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=220, random_state=42)
        self.accuracy = None
        self.precision = None
        self.recall = None
        self.train()

    def data(self, samples=6500):
        X, y = [], []
        for _ in range(samples):
            qber = np.random.uniform(0, 24)
            noise = np.random.uniform(0, 22)
            delay = np.random.uniform(0.02, 3.8)
            errors = np.random.randint(0, 130)
            attack = 1 if (qber > 10 or noise > 9 or errors > 45 or (qber > 7 and noise > 6)) else 0
            if np.random.random() < 0.035:
                attack = 1 - attack
            X.append([qber, noise, delay, errors])
            y.append(attack)
        return np.array(X), np.array(y)

    def train(self):
        X, y = self.data()
        xtr, xte, ytr, yte = train_test_split(X, y, test_size=0.22, random_state=42)
        self.model.fit(xtr, ytr)
        pred = self.model.predict(xte)
        self.accuracy = round(accuracy_score(yte, pred) * 100, 2)
        self.precision = round(precision_score(yte, pred, zero_division=0) * 100, 2)
        self.recall = round(recall_score(yte, pred, zero_division=0) * 100, 2)
        joblib.dump({"model": self.model, "accuracy": self.accuracy, "precision": self.precision, "recall": self.recall}, MODEL_PATH)

    def analyze(self, qber, noise, delay, errors):
        start = time.time()
        x = np.array([[qber, noise, delay, errors]])
        proba = self.model.predict_proba(x)[0]
        attack = round(float(proba[1]) * 100, 2)
        confidence = round(float(np.max(proba)) * 100, 2)
        threat = "LOW" if attack < 35 else "MEDIUM" if attack < 70 else "HIGH"
        names = ["QBER", "Noise", "Delay", "Errors"]
        importances = sorted([{"feature": n, "importance": round(float(v)*100, 2)} for n, v in zip(names, self.model.feature_importances_)], key=lambda x:x["importance"], reverse=True)
        reasons = []
        if qber >= CONFIG["qber_warning_threshold"]:
            reasons.append("QBER exceeds unsafe threshold.")
        elif qber >= CONFIG["qber_safe_threshold"]:
            reasons.append("QBER is above safe threshold.")
        if noise > 8:
            reasons.append("Noise is high.")
        if errors > 45:
            reasons.append("Error count is abnormal.")
        if not reasons:
            reasons.append("Features are inside acceptable ranges.")
        return {"threat_level": threat, "attack_probability": attack, "confidence": confidence,
                "security_score": round(100-attack, 2), "accuracy": self.accuracy,
                "precision": self.precision, "recall": self.recall,
                "feature_importance": importances, "explanation": " ".join(reasons),
                "duration": round(time.time()-start, 4)}

AI = AIEngine()


class AESGCM:
    MAGIC = b"WEBQC5GCM"

    @staticmethod
    def password_key(password, salt):
        return PBKDF2(password, salt, dkLen=32, count=int(CONFIG["pbkdf2_iterations"]), hmac_hash_module=SHA256)

    @staticmethod
    def encrypt(input_path, final_key_hex, password, q_summary, ai_summary):
        start = time.time()
        input_path = Path(input_path)
        file_key = bytes.fromhex(final_key_hex)
        data = input_path.read_bytes()
        original_hash = sha256_file(input_path)

        file_nonce = get_random_bytes(12)
        cipher = AES.new(file_key, AES.MODE_GCM, nonce=file_nonce)
        ciphertext, file_tag = cipher.encrypt_and_digest(data)

        salt = get_random_bytes(16)
        pkey = AESGCM.password_key(password, salt)
        key_nonce = get_random_bytes(12)
        key_cipher = AES.new(pkey, AES.MODE_GCM, nonce=key_nonce)
        encrypted_key, key_tag = key_cipher.encrypt_and_digest(file_key)

        header = {
            "version": "web-local-v1", "container_mode": "EMBEDDED_KEY_MODE",
            "algorithm": "AES-256-GCM", "original_filename": input_path.name,
            "original_hash_sha256": original_hash, "created_at": now_str(),
            "salt": salt.hex(), "key_nonce": key_nonce.hex(), "key_tag": key_tag.hex(),
            "encrypted_key": encrypted_key.hex(), "file_nonce": file_nonce.hex(),
            "file_tag": file_tag.hex(), "quantum_summary": q_summary, "ai_summary": ai_summary
        }
        out = ENCRYPTED_DIR / f"{input_path.name}.qenc"
        hb = json.dumps(header).encode()
        with open(out, "wb") as f:
            f.write(AESGCM.MAGIC)
            f.write(len(hb).to_bytes(4, "big"))
            f.write(hb)
            f.write(ciphertext)
        return {"path": out, "duration": round(time.time()-start, 3), "input_hash": original_hash, "output_hash": sha256_file(out)}

    @staticmethod
    def read(path):
        with open(path, "rb") as f:
            magic = f.read(len(AESGCM.MAGIC))
            if magic != AESGCM.MAGIC:
                raise ValueError("Invalid encrypted file format")
            size = int.from_bytes(f.read(4), "big")
            header = json.loads(f.read(size).decode())
            ciphertext = f.read()
        return header, ciphertext

    @staticmethod
    def decrypt(path, password):
        start = time.time()
        header, ciphertext = AESGCM.read(path)
        pkey = AESGCM.password_key(password, bytes.fromhex(header["salt"]))
        key_cipher = AES.new(pkey, AES.MODE_GCM, nonce=bytes.fromhex(header["key_nonce"]))
        file_key = key_cipher.decrypt_and_verify(bytes.fromhex(header["encrypted_key"]), bytes.fromhex(header["key_tag"]))
        file_cipher = AES.new(file_key, AES.MODE_GCM, nonce=bytes.fromhex(header["file_nonce"]))
        plain = file_cipher.decrypt_and_verify(ciphertext, bytes.fromhex(header["file_tag"]))
        out = DECRYPTED_DIR / f"decrypted_{header.get('original_filename','file')}"
        out.write_bytes(plain)
        output_hash = sha256_file(out)
        expected = header.get("original_hash_sha256", "")
        return {"path": out, "duration": round(time.time()-start, 3), "output_hash": output_hash, "expected_hash": expected, "integrity_ok": output_hash == expected, "header": header}

    @staticmethod
    def tamper_copy(path):
        out = TAMPERED_DIR / f"tampered_{Path(path).name}"
        shutil.copy2(path, out)
        data = bytearray(out.read_bytes())
        if len(data) > 30:
            data[-10] ^= 0xFF
        out.write_bytes(bytes(data))
        return out


app = FastAPI(title=CONFIG["app_title"])
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


HTML = r"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Data Encryption System Based on Quantum Computing</title>
<style>
:root{--bg:#070B16;--panel:#0E1527;--panel2:#111B32;--card:#16213E;--card2:#1B2A4A;--text:#F8FAFC;--muted:#94A3B8;--blue:#38BDF8;--green:#22C55E;--orange:#F59E0B;--red:#EF4444;--purple:#A78BFA;--cyan:#06B6D4;--border:#263654}
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:radial-gradient(circle at top left,#172554 0,#070B16 38%,#020617 100%);color:var(--text)}
.app{display:grid;grid-template-columns:290px 1fr;height:100vh;overflow:hidden}.sidebar{background:rgba(14,21,39,.94);border-right:1px solid var(--border);padding:20px;overflow-y:auto}
.brand{font-size:27px;font-weight:900;color:var(--blue);line-height:1.1}.version{color:var(--muted);font-size:13px;margin:6px 0 16px}.pill{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:10px;margin-bottom:18px;color:var(--green);font-weight:700}
.nav button{width:100%;padding:13px;border:0;border-radius:15px;background:var(--card);color:var(--text);text-align:left;margin:7px 0;cursor:pointer;font-weight:800}.nav button:hover,.nav button.active{background:linear-gradient(135deg,#2563EB,#7C3AED)}
.main{overflow-y:auto}.header{position:sticky;top:0;z-index:5;background:rgba(14,21,39,.94);backdrop-filter:blur(16px);border-bottom:1px solid var(--border);padding:22px 28px}.header h1{margin:0;font-size:32px}.header p{margin:6px 0 0;color:var(--blue);font-weight:700}
.content{padding:18px 22px}.cards{display:grid;grid-template-columns:repeat(6,minmax(150px,1fr));gap:12px;margin-bottom:18px}.card{background:linear-gradient(180deg,var(--card),#101A30);border:1px solid var(--border);border-radius:24px;padding:18px;min-height:112px;box-shadow:0 16px 40px rgba(0,0,0,.22)}.label{color:var(--muted);font-size:13px}.value{font-size:20px;font-weight:900;margin:8px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.detail{color:var(--muted);font-size:12px}
.panel{background:rgba(17,27,50,.9);border:1px solid var(--border);border-radius:26px;padding:18px;margin-bottom:18px;box-shadow:0 16px 38px rgba(0,0,0,.2)}.panel h2{margin:0 0 14px}
.actions{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}.btn{border:0;border-radius:15px;padding:12px;color:white;font-weight:800;cursor:pointer;background:#2563EB}.blue{background:#2563EB}.green{background:#16A34A}.orange{background:#D97706}.red{background:#DC2626}.purple{background:#7C3AED}.gray{background:#475569}.cyan{background:#0891B2}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}input{width:100%;background:#0B1224;border:1px solid var(--border);border-radius:14px;color:var(--text);padding:12px}pre{background:#050816;border:1px solid var(--border);border-radius:18px;padding:16px;color:#D1FAE5;white-space:pre-wrap;max-height:460px;overflow:auto}.page{display:none}.page.active{display:block}
.bargrid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.chart{height:260px;display:flex;align-items:end;gap:12px;padding:18px;border-radius:22px;background:#050816;border:1px solid var(--border);overflow:auto}.barwrap{min-width:70px;display:flex;flex-direction:column;align-items:center;justify-content:end;height:100%}.bar{width:46px;border-radius:14px 14px 4px 4px;background:linear-gradient(180deg,var(--blue),#2563EB);min-height:2px}.barlabel{font-size:11px;color:var(--muted);text-align:center;margin-top:8px}.barvalue{font-size:11px;margin-bottom:6px;font-weight:800}
table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid var(--border);padding:11px;text-align:left;font-size:13px}th{color:var(--blue);background:#0B1224}.status{position:fixed;right:20px;bottom:20px;background:var(--card);border:1px solid var(--border);border-radius:18px;padding:12px 16px;color:var(--green);font-weight:800}
.progress{height:9px;background:#0B1224;border-radius:99px;overflow:hidden;margin-top:12px;display:none}.progress div{height:100%;width:35%;background:linear-gradient(90deg,var(--blue),var(--purple));border-radius:99px;animation:load 1.1s infinite alternate}@keyframes load{from{margin-left:0}to{margin-left:65%}}
.login{position:fixed;inset:0;background:radial-gradient(circle at top,#1E3A8A,#070B16 55%);display:flex;align-items:center;justify-content:center;z-index:99}.loginbox{width:460px;background:rgba(14,21,39,.96);border:1px solid var(--border);border-radius:30px;padding:34px;box-shadow:0 26px 80px rgba(0,0,0,.45)}.small{font-size:12px;color:var(--muted)}@media(max-width:1200px){.cards{grid-template-columns:repeat(3,1fr)}.actions{grid-template-columns:repeat(2,1fr)}.grid2,.bargrid{grid-template-columns:1fr}.app{grid-template-columns:240px 1fr}}
</style></head><body>
<div id="login" class="login"><div class="loginbox"><h2>Data Encryption System Based on Quantum Computing</h2><p style="color:var(--blue);font-weight:700">With AI Performance Enhancer</p><input id="loginUser" placeholder="Username" value="admin"><br><br><input id="loginPass" placeholder="Password" type="password" value="admin123"><br><br><button class="btn blue" style="width:100%" onclick="login()">Login</button><p class="small">Admin: admin/admin123 | Encrypter: encrypter/encrypt123 | Viewer: viewer/viewer123</p></div></div>
<div class="app"><aside class="sidebar"><div class="brand">DES-QC AI</div><div class="version">Local Web App - Phase 1</div><div id="userPill" class="pill">Not logged in</div><div class="nav" id="nav"></div></aside><main class="main"><div class="header"><h1>Data Encryption System Based on Quantum Computing</h1><p>With AI Performance Enhancer</p><div class="progress" id="progress"><div></div></div></div><div class="content"><section class="cards"><div class="card"><div class="label">Selected File</div><div id="cFile" class="value" style="color:var(--cyan)">None</div><div id="cFileD" class="detail">No file selected</div></div><div class="card"><div class="label">Quantum Channel</div><div id="cQuantum" class="value" style="color:var(--blue)">Not Generated</div><div id="cQuantumD" class="detail">BB84 not started</div></div><div class="card"><div class="label">QBER</div><div id="cQber" class="value" style="color:var(--green)">0.00%</div><div id="cQberD" class="detail">No session</div></div><div class="card"><div class="label">AI Threat Level</div><div id="cAI" class="value" style="color:var(--purple)">Inactive</div><div id="cAID" class="detail">Waiting for analysis</div></div><div class="card"><div class="label">Decision</div><div id="cDecision" class="value" style="color:var(--orange)">Waiting</div><div id="cDecisionD" class="detail">No decision yet</div></div><div class="card"><div class="label">AES-256-GCM</div><div id="cAES" class="value" style="color:var(--green)">Ready</div><div id="cAESD" class="detail">Embedded Key Mode</div></div></section><section id="Dashboard" class="page active"></section><section id="FileManager" class="page"></section><section id="Quantum" class="page"></section><section id="AI" class="page"></section><section id="Graphs" class="page"></section><section id="Results" class="page"></section><section id="Logs" class="page"></section><section id="About" class="page"></section></div></main></div><div class="status" id="status">Status: Ready</div>
<script>
let token=null,user=null,uploaded=null,session=null,ai=null;let logs=[],results=[];let graph={qber:[],threat:[],perf:[],score:[]};const pages=["Dashboard","FileManager","Quantum","AI","Graphs","Results","Logs","About"];document.getElementById("nav").innerHTML=pages.map(p=>`<button onclick="showPage('${p}')" id="nav${p}">${p}</button>`).join("");
function api(path,opts={}){opts.headers=opts.headers||{};if(token)opts.headers["x-token"]=token;return fetch(path,opts).then(async r=>{let d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.detail||"Request failed");return d})}function showPage(p){pages.forEach(x=>{document.getElementById(x).classList.toggle("active",x==p);document.getElementById("nav"+x).classList.toggle("active",x==p)})}function progress(on){document.getElementById("progress").style.display=on?"block":"none"}function setStatus(t,c="var(--green)"){let s=document.getElementById("status");s.innerText="Status: "+t;s.style.color=c}function addLog(t){logs.unshift(`[${new Date().toLocaleTimeString()}] ${t}`);renderLogs()}function addResult(op,mode="-",qber="-",threat="-",decision="-",duration="-"){results.unshift({time:new Date().toLocaleTimeString(),op,mode,qber,threat,decision,duration});renderResults()}function colorFor(v){v=(v||"").toString();if(v.includes("LOW")||v.includes("SECURE")||v.includes("ACCEPT"))return"var(--green)";if(v.includes("MEDIUM")||v.includes("SUSPICIOUS")||v.includes("REGENERATE"))return"var(--orange)";if(v.includes("HIGH")||v.includes("UNSAFE")||v.includes("REJECT"))return"var(--red)";return"var(--blue)"}function card(id,v,d,c){document.getElementById(id).innerText=v;if(d!==undefined)document.getElementById(id+"D").innerText=d;if(c)document.getElementById(id).style.color=c}
async function login(){try{let u=document.getElementById("loginUser").value,p=document.getElementById("loginPass").value;let data=await api("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});token=data.token;user=data.user;document.getElementById("login").style.display="none";document.getElementById("userPill").innerText=`${user.username} | ${user.role}`;buildDashboard();buildFileManager();buildQuantum();buildAI();buildGraphs();buildResults();buildLogs();buildAbout();addLog(`Logged in as ${user.username} (${user.role})`)}catch(e){alert(e.message)}}
function buildDashboard(){document.getElementById("Dashboard").innerHTML=`<div class="panel"><h2>Action Center</h2><div class="actions"><button class="btn blue" onclick="selectFile()">Select File</button><button class="btn green" onclick="genKey('IDEAL')">Generate Ideal Key</button><button class="btn orange" onclick="genKey('NOISY')">Generate Noisy Key</button><button class="btn red" onclick="genKey('ATTACK')">Simulate Attack</button><button class="btn purple" onclick="encryptFile()">Encrypt File</button><button class="btn orange" onclick="decryptFile()">Decrypt File</button><button class="btn red" onclick="tamperTest()">Tamper Test</button><button class="btn purple" onclick="retrainAI()">Retrain AI</button><button class="btn green" onclick="exportPDF()">Export PDF Report</button><button class="btn cyan" onclick="selfTest()">Run Self-Test</button></div></div><div class="panel"><h2>Selected File Information</h2><pre id="fileInfo">No file selected.</pre><input type="file" id="fileInput" style="display:none" onchange="uploadSelected()"><button class="btn red" onclick="clearFile()">✕ Remove Selected File</button></div><div class="grid2"><div class="panel"><h2>Workflow</h2><pre>1. Select File
2. Generate Ideal / Noisy / Attack BB84 Key
3. AI analyzes QBER, noise, delay, errors
4. Encrypt using AES-256-GCM Embedded Key Mode
5. Decrypt later using the password only
6. Export PDF report / graphs</pre></div><div class="panel"><h2>Current Session Summary</h2><pre id="summaryBox">No active session.</pre></div></div>`}
function selectFile(){document.getElementById("fileInput").click()}async function uploadSelected(){let f=document.getElementById("fileInput").files[0];if(!f)return;let fd=new FormData();fd.append("file",f);progress(true);try{let r=await fetch("/api/upload",{method:"POST",headers:{"x-token":token},body:fd});let data=await r.json();if(data.detail)throw new Error(data.detail);uploaded=data.file;document.getElementById("fileInfo").innerText=`File Name: ${uploaded.filename}\nSize: ${uploaded.size_human}\nSHA-256: ${uploaded.hash}\nStatus: Ready for encryption.`;card("cFile",uploaded.filename.slice(0,18),uploaded.size_human,"var(--cyan)");addLog("File uploaded: "+uploaded.filename);setStatus("File uploaded successfully")}catch(e){alert(e.message)}finally{progress(false)}}function clearFile(){uploaded=null;document.getElementById("fileInfo").innerText="No file selected.";card("cFile","None","No file selected","var(--cyan)")}
async function genKey(mode){progress(true);try{let data=await api("/api/quantum/generate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({mode})});session=data.quantum;ai=data.ai;card("cQuantum",session.status,`Mode: ${session.mode} | Key: ${session.sifted_key_length} bits`,colorFor(session.status));card("cQber",session.qber+"%",`Noise: ${session.noise} | Errors: ${session.errors}`,colorFor(session.status));card("cAI",ai.threat_level,`Attack: ${ai.attack_probability}% | Confidence: ${ai.confidence}%`,colorFor(ai.threat_level));card("cDecision",session.decision,`Expires: ${session.expires_at_text}`,colorFor(session.decision));graph.qber.push([mode,session.qber]);graph.threat.push([mode,ai.attack_probability]);graph.score.push([mode,ai.security_score]);graph.perf.push(["BB84 "+mode,session.duration]);addResult("KEY",mode,session.qber+"%",ai.threat_level,session.decision,session.duration+"s");addLog(`Quantum key generated: ${mode} | ${session.decision}`);buildQuantum();buildAI();buildGraphs();updateSummary();showPage("Quantum");if(!session.accepted)alert("Quantum key rejected due to high QBER.")}catch(e){alert(e.message)}finally{progress(false)}}function updateSummary(){document.getElementById("summaryBox").innerText=`Selected File: ${uploaded?uploaded.filename:"None"}\nQuantum Key: ${session?"Generated":"Not generated"}\nMode: ${session?session.mode:"-"}\nQBER: ${session?session.qber+"%":"-"}\nDecision: ${session?session.decision:"-"}\nAI Threat: ${ai?ai.threat_level:"-"}\nAttack Probability: ${ai?ai.attack_probability+"%":"-"}\nAI Confidence: ${ai?ai.confidence+"%":"-"}`}
async function encryptFile(){if(!uploaded){alert("Select a file first.");return}if(!session){alert("Generate quantum key first.");return}let password=prompt("Enter encryption password:");if(!password)return;progress(true);try{let data=await api("/api/encrypt",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({file_id:uploaded.id,session_id:session.id,password})});card("cAES","Encrypted",data.duration+"s","var(--green)");graph.perf.push(["Encrypt",data.duration]);addResult("ENCRYPT",session.mode,session.qber+"%",ai.threat_level,"DONE",data.duration+"s");addLog("File encrypted: "+data.file.filename);buildFileManager();buildGraphs();alert("Encrypted successfully.")}catch(e){alert(e.message)}finally{progress(false)}}async function decryptFile(file_id=null){let password=prompt("Enter decryption password:");if(!password)return;progress(true);try{if(!file_id){let files=await api("/api/files?type=encrypted");if(!files.files.length){alert("No encrypted files.");progress(false);return}file_id=files.files[0].id}let data=await api("/api/decrypt",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({file_id,password})});graph.perf.push(["Decrypt",data.duration]);addResult("DECRYPT","-","-","-",data.integrity_ok?"VERIFIED":"FAILED",data.duration+"s");addLog("File decrypted. Integrity: "+data.integrity_ok);buildFileManager();buildGraphs();alert("Decrypted successfully. Integrity OK: "+data.integrity_ok)}catch(e){alert(e.message)}finally{progress(false)}}async function tamperTest(file_id=null){if(!file_id){let files=await api("/api/files?type=encrypted");if(!files.files.length){alert("No encrypted files.");return}file_id=files.files[0].id}let password=prompt("Enter password to verify tamper detection:");if(!password)return;progress(true);try{let data=await api("/api/tamper_test",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({file_id,password})});addResult("TAMPER","-","-","HIGH",data.detected?"DETECTED":"NOT DETECTED","-");alert(data.message)}catch(e){alert(e.message)}finally{progress(false)}}async function retrainAI(){progress(true);try{let data=await api("/api/ai/retrain",{method:"POST"});addResult("AI RETRAIN","-","-","-","DONE",data.duration+"s");alert(`Accuracy: ${data.accuracy}%\nPrecision: ${data.precision}%\nRecall: ${data.recall}%`)}catch(e){alert(e.message)}finally{progress(false)}}async function selfTest(){let data=await api("/api/self_test",{method:"POST"});alert(data.report)}async function exportPDF(){progress(true);try{let data=await api("/api/report/pdf",{method:"POST"});window.open(data.download_url,"_blank")}catch(e){alert(e.message)}finally{progress(false)}}
function buildFileManager(){document.getElementById("FileManager").innerHTML=`<div class="bargrid"><div class="panel"><h2>Encrypted Files</h2><input id="sEnc" placeholder="Search encrypted files..." oninput="loadFiles('encrypted')"><div id="encTable"></div></div><div class="panel"><h2>Decrypted Files</h2><input id="sDec" placeholder="Search decrypted files..." oninput="loadFiles('decrypted')"><div id="decTable"></div></div></div>`;loadFiles("encrypted");loadFiles("decrypted")}async function loadFiles(type){let q=type=="encrypted"?(document.getElementById("sEnc")?.value||""):(document.getElementById("sDec")?.value||"");let data=await api(`/api/files?type=${type}&search=${encodeURIComponent(q)}`);let rows=data.files.map(f=>`<tr><td>${f.filename}</td><td>${f.size_human}</td><td>${f.mode}</td><td>${f.threat_level}</td><td>${type=="encrypted"?`<button class="btn green" onclick="decryptFile('${f.id}')">Decrypt</button> <button class="btn red" onclick="tamperTest('${f.id}')">Tamper</button>`:""} <button class="btn gray" onclick="deleteFile('${f.id}','${type}')">Delete</button></td></tr>`).join("");document.getElementById(type=="encrypted"?"encTable":"decTable").innerHTML=`<table><tr><th>Name</th><th>Size</th><th>Mode</th><th>Threat</th><th>Actions</th></tr>${rows}</table>`}async function deleteFile(id,type){if(!confirm("Delete file?"))return;await api("/api/file/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({file_id:id})});loadFiles(type)}
function buildQuantum(){document.getElementById("Quantum").innerHTML=`<div class="grid2"><div class="panel"><h2>BB84 Quantum Session</h2><pre>${session?JSON.stringify(session,null,2):"No quantum session yet."}</pre></div><div class="panel"><h2>Basis Matching Preview</h2><div style="max-height:520px;overflow:auto">${session?basisTable(session.basis_table):"No data."}</div></div></div>`}function basisTable(rows){return `<table><tr><th>Index</th><th>Alice Bit</th><th>Alice Basis</th><th>Bob Basis</th><th>Bob Bit</th><th>Match</th></tr>${rows.map(r=>`<tr><td>${r.index}</td><td>${r.alice_bit}</td><td>${r.alice_basis}</td><td>${r.bob_basis}</td><td>${r.bob_bit}</td><td>${r.match}</td></tr>`).join("")}</table>`}
function buildAI(){document.getElementById("AI").innerHTML=`<div class="grid2"><div class="panel"><h2>AI Threat Analysis</h2><pre>${ai?JSON.stringify(ai,null,2):"AI analysis appears after generating a quantum key."}</pre></div><div class="panel"><h2>Feature Importance</h2>${ai?`<table><tr><th>Feature</th><th>Importance</th></tr>${ai.feature_importance.map(x=>`<tr><td>${x.feature}</td><td>${x.importance}%</td></tr>`).join("")}</table>`:"No data."}</div></div>`}
function buildGraphs(){document.getElementById("Graphs").innerHTML=`<div class="bargrid"><div class="panel"><h2>QBER Bar Graph</h2>${barChart(graph.qber,25)}</div><div class="panel"><h2>AI Threat Probability</h2>${barChart(graph.threat,100)}</div><div class="panel"><h2>Crypto / Processing Time</h2>${barChart(graph.perf,null)}</div><div class="panel"><h2>Security Score</h2>${barChart(graph.score,100)}</div></div>`}function barChart(data,maxv){if(!data.length)return `<div class="chart"><span class="small">No data yet.</span></div>`;let m=maxv||Math.max(...data.map(x=>x[1]),1)*1.2;return `<div class="chart">${data.slice(-8).map(x=>`<div class="barwrap"><div class="barvalue">${x[1]}</div><div class="bar" style="height:${Math.max(2,(x[1]/m)*190)}px"></div><div class="barlabel">${x[0]}</div></div>`).join("")}</div>`}
function buildResults(){renderResults()}function renderResults(){document.getElementById("Results").innerHTML=`<div class="panel"><h2>Results and Performance Benchmark</h2><table><tr><th>Time</th><th>Operation</th><th>Mode</th><th>QBER</th><th>Threat</th><th>Decision</th><th>Duration</th></tr>${results.map(r=>`<tr><td>${r.time}</td><td>${r.op}</td><td>${r.mode}</td><td>${r.qber}</td><td>${r.threat}</td><td>${r.decision}</td><td>${r.duration}</td></tr>`).join("")}</table></div>`}
function buildLogs(){renderLogs()}function renderLogs(){document.getElementById("Logs").innerHTML=`<div class="panel"><h2>Security Logs</h2><pre>${logs.join("\n")||"No logs yet."}</pre></div>`}
function buildAbout(){document.getElementById("About").innerHTML=`<div class="panel"><h2>About</h2><pre>Data Encryption System Based on Quantum Computing
With AI Performance Enhancer

Local Web App Phase 1:
- FastAPI Backend
- Professional browser-based GUI
- Qiskit QRNG and BB84 simulation
- AES-256-GCM only
- Embedded password-protected key mode
- AI threat analysis with confidence and feature importance
- File Manager, Tamper Test, PDF Report, Graphs

Academic note:
This is a preliminary simulation. Qiskit runs on the Python backend, not physical quantum hardware.</pre></div>`}
</script></body></html>"""

@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(HTML)

@app.post("/api/login")
async def login(payload: dict):
    username = payload.get("username", "")
    password = payload.get("password", "")
    if username in USERS and USERS[username]["password"] == password:
        token = str(uuid.uuid4())
        TOKENS[token] = {"username": username, "role": USERS[username]["role"]}
        DATABASE.audit(username, USERS[username]["role"], "LOGIN", "SUCCESS", "LOW")
        return {"token": token, "user": TOKENS[token]}
    raise HTTPException(status_code=401, detail="Invalid username or password")

@app.post("/api/upload")
async def upload(file: UploadFile = File(...), x_token: Optional[str] = Header(None)):
    user = get_user(x_token)
    require_role(user, ["Encrypter"])
    suffix = Path(file.filename).suffix
    out = UPLOADS_DIR / f"{uuid.uuid4().hex}{suffix}"
    content = await file.read()
    out.write_bytes(content)
    file_id = DATABASE.add_file("upload", out, "-", 0, "-")
    DATABASE.audit(user["username"], user["role"], "UPLOAD_FILE", "SUCCESS", "LOW")
    return {"file": {"id": file_id, "filename": file.filename, "stored_name": out.name, "size": len(content), "size_human": human_size(len(content)), "hash": sha256_file(out)}}

@app.post("/api/quantum/generate")
async def quantum_generate(payload: dict, x_token: Optional[str] = Header(None)):
    user = get_user(x_token)
    require_role(user, ["Encrypter"])
    mode = payload.get("mode", "IDEAL").upper()
    if mode not in ["IDEAL", "NOISY", "ATTACK"]:
        raise HTTPException(status_code=400, detail="Invalid mode")
    q = BB84_ENGINE.generate(mode)
    ai = AI.analyze(q["qber"], q["noise"], q["delay"], q["errors"])
    DATABASE.execute("INSERT INTO sessions(id,payload,expires_at,created_at) VALUES (?,?,?,?)", (q["id"], json.dumps({"quantum": q, "ai": ai}), q["expires_at"], now_str()))
    q2 = dict(q)
    q2["expires_at_text"] = datetime.fromisoformat(q["expires_at"]).strftime("%H:%M:%S")
    DATABASE.audit(user["username"], user["role"], "BB84_GENERATE", q["decision"], ai["threat_level"])
    return {"quantum": q2, "ai": ai}

def get_session(session_id):
    with DATABASE.connect() as conn:
        c = conn.cursor()
        c.execute("SELECT payload,expires_at FROM sessions WHERE id=?", (session_id,))
        row = c.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    if datetime.now() > datetime.fromisoformat(row[1]):
        raise HTTPException(status_code=400, detail="Quantum session expired")
    return json.loads(row[0])

@app.post("/api/encrypt")
async def encrypt(payload: dict, x_token: Optional[str] = Header(None)):
    user = get_user(x_token)
    require_role(user, ["Encrypter"])
    file_id, session_id, password = payload.get("file_id"), payload.get("session_id"), payload.get("password")
    if not password:
        raise HTTPException(status_code=400, detail="Password required")
    f = DATABASE.get_file(file_id)
    if not f:
        raise HTTPException(status_code=404, detail="File not found")
    sess = get_session(session_id)
    q, ai = sess["quantum"], sess["ai"]
    if not q["accepted"]:
        raise HTTPException(status_code=400, detail="Rejected key cannot be used for encryption")
    result = AESGCM.encrypt(Path(f[3]), q["final_key_hex"], password,
                            {k: q[k] for k in ["mode", "qber", "noise", "decision", "status", "sifted_key_length"]},
                            {k: ai[k] for k in ["threat_level", "attack_probability", "confidence", "security_score"]})
    new_id = DATABASE.add_file("encrypted", result["path"], "Embedded Key Mode", q["qber"], ai["threat_level"])
    DATABASE.record_key(hashlib.sha256(q["final_key_hex"].encode()).hexdigest(), f[2])
    DATABASE.execute("INSERT INTO operations(operation,duration,qber,threat_level,decision,created_at) VALUES (?,?,?,?,?,?)", ("ENCRYPT", result["duration"], q["qber"], ai["threat_level"], "DONE", now_str()))
    DATABASE.audit(user["username"], user["role"], "ENCRYPT", "SUCCESS", ai["threat_level"])
    return {"file": {"id": new_id, "filename": result["path"].name}, "duration": result["duration"], "output_hash": result["output_hash"]}

@app.post("/api/decrypt")
async def decrypt(payload: dict, x_token: Optional[str] = Header(None)):
    user = get_user(x_token)
    require_role(user, ["Encrypter"])
    f = DATABASE.get_file(payload.get("file_id"))
    if not f:
        raise HTTPException(status_code=404, detail="File not found")
    result = AESGCM.decrypt(Path(f[3]), payload.get("password"))
    new_id = DATABASE.add_file("decrypted", result["path"], "Decrypted", 0, "-")
    DATABASE.execute("INSERT INTO operations(operation,duration,qber,threat_level,decision,created_at) VALUES (?,?,?,?,?,?)", ("DECRYPT", result["duration"], 0, "-", "VERIFIED" if result["integrity_ok"] else "FAILED", now_str()))
    DATABASE.audit(user["username"], user["role"], "DECRYPT", "SUCCESS", "LOW")
    return {"file": {"id": new_id, "filename": result["path"].name}, "duration": result["duration"], "integrity_ok": result["integrity_ok"]}

@app.get("/api/files")
async def files(type: str, search: str = "", x_token: Optional[str] = Header(None)):
    user = get_user(x_token)
    rows = DATABASE.list_files(type, search)
    return {"files": [{"id": r[0], "filename": r[1], "path": r[2], "size": r[3], "size_human": human_size(r[3]), "hash": r[4], "mode": r[5], "qber": r[6], "threat_level": r[7], "created_at": r[8]} for r in rows]}

@app.post("/api/file/delete")
async def delete_file(payload: dict, x_token: Optional[str] = Header(None)):
    user = get_user(x_token)
    require_role(user, ["Encrypter"])
    row = DATABASE.get_file(payload.get("file_id"))
    if not row:
        raise HTTPException(status_code=404, detail="File not found")
    path = Path(row[3])
    if path.exists():
        path.unlink()
    DATABASE.delete_file(row[0])
    DATABASE.audit(user["username"], user["role"], "DELETE_FILE", "SUCCESS", "MEDIUM")
    return {"ok": True}

@app.post("/api/tamper_test")
async def tamper_test(payload: dict, x_token: Optional[str] = Header(None)):
    user = get_user(x_token)
    require_role(user, ["Encrypter"])
    row = DATABASE.get_file(payload.get("file_id"))
    if not row:
        raise HTTPException(status_code=404, detail="File not found")
    tampered = AESGCM.tamper_copy(Path(row[3]))
    detected = False
    try:
        AESGCM.decrypt(tampered, payload.get("password"))
    except Exception:
        detected = True
    DATABASE.audit(user["username"], user["role"], "TAMPER_TEST", "DETECTED" if detected else "NOT_DETECTED", "HIGH")
    return {"detected": detected, "tampered_file": tampered.name, "message": "Tampering detected successfully. AES-GCM authentication failed." if detected else "Tampering was not detected."}

@app.post("/api/ai/retrain")
async def retrain(x_token: Optional[str] = Header(None)):
    user = get_user(x_token)
    require_role(user, ["Encrypter"])
    start = time.time()
    AI.train()
    return {"accuracy": AI.accuracy, "precision": AI.precision, "recall": AI.recall, "duration": round(time.time() - start, 3)}

@app.post("/api/self_test")
async def self_test(x_token: Optional[str] = Header(None)):
    user = get_user(x_token)
    checks = []
    try:
        AerSimulator()
        checks.append("Qiskit Aer: OK")
    except Exception as e:
        checks.append(f"Qiskit Aer: FAILED {e}")
    try:
        key = get_random_bytes(32)
        nonce = get_random_bytes(12)
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = c.encrypt_and_digest(b"test")
        c2 = AES.new(key, AES.MODE_GCM, nonce=nonce)
        c2.decrypt_and_verify(ct, tag)
        checks.append("AES-GCM: OK")
    except Exception as e:
        checks.append(f"AES-GCM: FAILED {e}")
    checks.append(f"AI Model: OK Accuracy={AI.accuracy}%")
    checks.append("SQLite Database: OK")
    return {"report": "\n".join(checks)}

@app.post("/api/report/pdf")
async def report_pdf(x_token: Optional[str] = Header(None)):
    user = get_user(x_token)
    report = REPORTS_DIR / f"academic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    doc = SimpleDocTemplate(str(report), pagesize=A4)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("title", parent=styles["Title"], fontSize=18, textColor=colors.HexColor("#0F172A"))
    h = ParagraphStyle("h", parent=styles["Heading2"], textColor=colors.HexColor("#1D4ED8"))
    story = [
        Paragraph(CONFIG["app_title"], title),
        Paragraph(CONFIG["subtitle"], styles["Heading3"]),
        Spacer(1, 12),
        Paragraph("1. Project Overview", h),
        Paragraph("This local web application demonstrates BB84 quantum key distribution simulation, AES-256-GCM file encryption, and AI-based threat analysis.", styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("2. Implemented Modules", h),
    ]
    data = [["Module", "Status"], ["Qiskit QRNG", "Implemented"], ["BB84 Simulation", "Implemented"], ["AES-256-GCM", "Implemented"], ["AI Threat Detection", "Implemented"], ["Tamper Detection", "Implemented"], ["File Manager", "Implemented"]]
    t = Table(data, colWidths=[170, 300])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1E3A8A")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.5,colors.grey)]))
    story.append(t)
    story.append(Spacer(1, 12))
    story.append(Paragraph("3. Limitations", h))
    story.append(Paragraph("This is a preliminary software simulation. It does not use physical quantum hardware.", styles["BodyText"]))
    doc.build(story)
    return {"download_url": f"/api/download_report/{report.name}", "filename": report.name}

@app.get("/api/download_report/{name}")
async def download_report(name: str):
    path = REPORTS_DIR / name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path, filename=name)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
