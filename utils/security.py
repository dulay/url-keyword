from collections import defaultdict
from flask import abort, session

ip_stats = defaultdict(list)
MAX_IPS = 20

def ip_record(request, user):
    ip = request.remote_addr
    if user and hasattr(user, "name"):
        ip_stats[user.name].append(ip)
        if len(ip_stats[user.name]) > MAX_IPS:
            ip_stats[user.name] = ip_stats[user.name][-MAX_IPS:]

def check_abnormal_ip(request, session):
    ip = request.remote_addr
    if 'user_name' in session:
        ips = ip_stats.get(session['user_name'], [])
        if len(ips) >= 5 and ip not in ips:
            abort(403)
