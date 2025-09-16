from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import pandas as pd
import os
import pickle
from datetime import datetime

USER_FILE = 'users.csv'
IP_LOG_FILE = 'user_ips.pkl'
OP_LOG_FILE = 'user_ops.pkl'

class User(UserMixin):
    def __init__(self, name, password_hash, approved=False, is_admin=False):
        self.id = name
        self.name = name
        self.password_hash = password_hash
        self.approved = bool(approved)
        self.is_admin = bool(is_admin)

users = {}

def _load_users():
    users.clear()
    if os.path.exists(USER_FILE):
        df = pd.read_csv(USER_FILE)
        for _, row in df.iterrows():
            users[row['name']] = User(
                row['name'],
                row['password_hash'],
                row.get('approved', False),
                row.get('is_admin', False)
            )

def _save_users():
    df = pd.DataFrame([vars(u) for u in users.values()])
    df.to_csv(USER_FILE, index=False)

def add_user(name, password, is_admin=False):
    _load_users()
    users[name] = User(name, generate_password_hash(password), False, is_admin)
    _save_users()

def approve_user(name):
    _load_users()
    if name in users:
        users[name].approved = True
    _save_users()

def get_user_by_name(name):
    _load_users()
    return users.get(name)

def get_unapproved_users():
    _load_users()
    return [u for u in users.values() if not u.approved]

def change_user_password(name, old_password, new_password):
    _load_users()
    user = users.get(name)
    if user and check_password_hash(user.password_hash, old_password):
        user.password_hash = generate_password_hash(new_password)
        _save_users()
        return True
    return False

def record_login_ip(name, ip):
    if not name: return
    iplog = {}
    if os.path.exists(IP_LOG_FILE):
        with open(IP_LOG_FILE, "rb") as f:
            iplog = pickle.load(f)
    iplog.setdefault(name, [])
    if ip not in iplog[name]:
        iplog[name].insert(0, ip)
    iplog[name] = iplog[name][:10]
    with open(IP_LOG_FILE, "wb") as f:
        pickle.dump(iplog, f)

def get_user_ips(name):
    if not os.path.exists(IP_LOG_FILE): return []
    with open(IP_LOG_FILE, "rb") as f:
        iplog = pickle.load(f)
    return iplog.get(name, [])

def record_user_op(name, op):
    if not name: return
    oplog = {}
    if os.path.exists(OP_LOG_FILE):
        with open(OP_LOG_FILE, "rb") as f:
            oplog = pickle.load(f)
    oplog.setdefault(name, [])
    oplog[name].insert(0, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), op))
    oplog[name] = oplog[name][:30]
    with open(OP_LOG_FILE, "wb") as f:
        pickle.dump(oplog, f)

def get_user_ops(name):
    if not os.path.exists(OP_LOG_FILE): return []
    with open(OP_LOG_FILE, "rb") as f:
        oplog = pickle.load(f)
    return oplog.get(name, [])
