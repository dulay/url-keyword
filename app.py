import os
import uuid
import threading
import re
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort, jsonify, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.excel_utils import create_template, read_excel, write_excel
from utils.crawler import check_keyword_in_url
from utils.security import ip_record, check_abnormal_ip
from utils.user_mgmt import (
    User, users, add_user, approve_user, get_user_by_name, get_unapproved_users,
    change_user_password, record_login_ip, get_user_ips, record_user_op, get_user_ops
)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change_this_for_prod")

UPLOAD_FOLDER = 'uploads'
RESULT_FOLDER = 'results'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

TASKS_FILE = 'tasks.csv'
if not os.path.exists(TASKS_FILE):
    pd.DataFrame(columns=['id', 'user', 'name', 'time', 'status', 'filename', 'progress']).to_csv(TASKS_FILE, index=False)

def add_task(user, name, status, filename):
    df = pd.read_csv(TASKS_FILE)
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    task_id = str(uuid.uuid4())
    df.loc[len(df)] = [task_id, user, name, now, status, filename, 0]
    df.to_csv(TASKS_FILE, index=False)
    return task_id

def update_task_status(task_id, status):
    df = pd.read_csv(TASKS_FILE)
    df.loc[df['id'] == task_id, 'status'] = status
    df.to_csv(TASKS_FILE, index=False)

def update_task_progress(task_id, progress):
    df = pd.read_csv(TASKS_FILE)
    df.loc[df['id'] == task_id, 'progress'] = progress
    df.to_csv(TASKS_FILE, index=False)

def get_user_tasks(user):
    df = pd.read_csv(TASKS_FILE)
    return df[df['user'] == user].sort_values(by="time", ascending=False).to_dict(orient='records')

def get_task_info(task_id):
    df = pd.read_csv(TASKS_FILE)
    row = df.loc[df['id'] == task_id]
    if not row.empty:
        return row.iloc[0].to_dict()
    return {}

latest_progress = {"current": "", "http_code": "", "result": "", "cur_idx": 0, "total": 0}
latest_progress_lock = threading.Lock()
in_progress_details = {}
in_progress_lock = threading.Lock()

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@app.before_request
def before_req():
    if current_user.is_authenticated:
        ip_record(request, current_user)
        record_login_ip(current_user.name, request.remote_addr)
    check_abnormal_ip(request, session)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not re.match(r'^[a-zA-Z0-9_]{4,20}$', username):
            flash("用户名需4-20位字母、数字或下划线")
            return render_template('register.html')
        if get_user_by_name(username):
            flash("用户名已存在")
            return render_template('register.html')
        add_user(username, password)
        flash("注册成功，请等待管理员审核")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = get_user_by_name(username)
        if user and user.approved and check_password_hash(user.password_hash, password):
            login_user(user)
            record_user_op(username, "登录成功")
            record_login_ip(username, request.remote_addr)
            return redirect(url_for('index'))
        elif user and not user.approved:
            flash("用户待审核，请联系管理员")
        else:
            flash("用户名或密码错误")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    record_user_op(current_user.name, "退出登录")
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not getattr(current_user, "is_admin", False):
        abort(403)
    if request.method == 'POST':
        approve_user(request.form.get('username'))
        record_user_op(current_user.name, f"审核通过用户 {request.form.get('username')}")
    unapproved = get_unapproved_users()
    return render_template('admin.html', unapproved=unapproved)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    msg = None
    if request.method == 'POST':
        old = request.form.get('old_password')
        new = request.form.get('new_password')
        new2 = request.form.get('new_password2')
        if not old or not new or not new2:
            msg = "请填写完整"
        elif new != new2:
            msg = "两次新密码不一致"
        else:
            ok = change_user_password(current_user.name, old, new)
            if ok:
                record_user_op(current_user.name, "修改密码")
                msg = "修改成功"
            else:
                msg = "原密码错误"
        flash(msg)
    login_ips = get_user_ips(current_user.name)
    op_logs = get_user_ops(current_user.name)
    return render_template("profile.html", login_ips=login_ips, op_logs=op_logs)

@app.route('/download/template')
@login_required
def download_template():
    path = os.path.join(UPLOAD_FOLDER, "template.xlsx")
    create_template(path)
    return send_file(path, as_attachment=True)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    name = request.form.get('name', '').strip()
    if not name:
        flash("请填写核查名称")
        return redirect(url_for('index'))
    file = request.files['file']
    if not file or not file.filename.endswith('.xlsx'):
        flash('只允许上传xlsx格式文件')
        return redirect(url_for('index'))
    filename = f"{uuid.uuid4()}.xlsx"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    task_id = add_task(current_user.name, name, "核查中", filename)
    threading.Thread(target=run_task_multithread, args=(task_id, filepath)).start()
    record_user_op(current_user.name, f"提交核查任务 {name}")
    flash('任务已提交，稍后可在历史任务中查看进度')
    return redirect(url_for('tasks'))

def run_task_multithread(task_id, filepath):
    try:
        df = read_excel(filepath)
        n = len(df)
        results, titles, codes, ratios, matchinfo = [""]*n, [""]*n, [""]*n, [""]*n, [""]*n
        def process_row(idx, url, kw):
            return check_keyword_in_url(url, kw)
        with ThreadPoolExecutor(max_workers=10) as executor:
            fut2idx = {}
            for i, row in df.iterrows():
                url = str(row.get('URL', '')).strip()
                kw = str(row.get('关键词', '')).strip()
                fut = executor.submit(process_row, i, url, kw)
                fut2idx[fut] = (i, url)
            done = 0
            for fut in as_completed(fut2idx):
                idx, url = fut2idx[fut]
                try:
                    res, title, code, ratio, info = fut.result()
                except Exception:
                    res, title, code, ratio, info = "核查失败", "", 0, 0, ""
                results[idx] = res
                titles[idx] = title
                codes[idx] = code
                ratios[idx] = f"{ratio}%"
                matchinfo[idx] = info
                done += 1
                progress = int(done / n * 100)
                update_task_progress(task_id, progress)
                with latest_progress_lock:
                    latest_progress.update({"current": url, "http_code": code, "result": res, "cur_idx": done, "total": n})
                with in_progress_lock:
                    in_progress_details[task_id] = {
                        "current": url, "current_idx": idx+1, "total": n,
                        "http_code": code, "result": res, "progress": progress
                    }
        df['核查结果'] = results
        df['title'] = titles
        df['http_code'] = codes
        df['关键词占比'] = ratios
        df['匹配详情'] = matchinfo
        result_file = os.path.join(RESULT_FOLDER, f"{task_id}.xlsx")
        write_excel(df, result_file)
        update_task_status(task_id, "已完成")
        update_task_progress(task_id, 100)
        with in_progress_lock:
            if task_id in in_progress_details:
                del in_progress_details[task_id]
        with latest_progress_lock:
            latest_progress.update({"current": "", "http_code": "", "result": "", "cur_idx": 0, "total": 0})
    except Exception:
        update_task_status(task_id, "失败")
        update_task_progress(task_id, 0)
        with in_progress_lock:
            if task_id in in_progress_details:
                in_progress_details[task_id]['result'] = "失败"
        with latest_progress_lock:
            latest_progress.update({"current": "", "http_code": "", "result": "失败", "cur_idx": 0, "total": 0})

@app.route('/tasks')
@login_required
def tasks():
    mytasks = get_user_tasks(current_user.name)
    return render_template('tasks.html', tasks=mytasks)

@app.route('/result/<task_id>')
@login_required
def result(task_id):
    result_file = os.path.join(RESULT_FOLDER, f"{task_id}.xlsx")
    if not os.path.exists(result_file):
        abort(404)
    df = read_excel(result_file)
    rows = df.to_dict(orient='records')
    counts = {
        "total": len(df),
        "exist": (df['核查结果'] == "仍存在").sum(),
        "del": (df['核查结果'] == "已删除").sum(),
        "fail": (df['核查结果'] == "核查失败").sum()
    }
    info = get_task_info(task_id)
    progress = info.get('progress', 0)
    status = info.get('status', '')
    return render_template(
        'result.html',
        task_id=task_id,
        columns=df.columns,
        rows=rows,
        counts=counts,
        progress=progress,
        status=status,
        task=info   # <--修复点
    )

@app.route('/progress/<task_id>')
@login_required
def progress_api(task_id):
    with in_progress_lock:
        data = in_progress_details.get(task_id, {})
    info = get_task_info(task_id)
    if data:
        data['status'] = info.get('status', '')
    else:
        data = {'progress': info.get('progress', 0), 'status': info.get('status', '')}
    return jsonify(data)

@app.route('/progress_home')
def progress_home_api():
    with latest_progress_lock:
        data = dict(latest_progress)
    return jsonify(data)

@app.route('/download/result/<task_id>')
@login_required
def download_result(task_id):
    result_file = os.path.join(RESULT_FOLDER, f"{task_id}.xlsx")
    if not os.path.exists(result_file):
        abort(404)
    record_user_op(current_user.name, f"下载结果 {task_id}")
    return send_file(result_file, as_attachment=True)

@app.route('/share/<task_id>')
@login_required
def share(task_id):
    return redirect(url_for('result', task_id=task_id, _external=True))

@app.route('/delete_task/<task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    df = pd.read_csv(TASKS_FILE)
    info = get_task_info(task_id)
    df = df[df['id'] != task_id]
    df.to_csv(TASKS_FILE, index=False)
    # 删除上传文件和结果文件
    if info.get('filename'):
        upload_path = os.path.join(UPLOAD_FOLDER, info['filename'])
        if os.path.exists(upload_path):
            os.remove(upload_path)
    result_path = os.path.join(RESULT_FOLDER, f"{task_id}.xlsx")
    if os.path.exists(result_path):
        os.remove(result_path)
    record_user_op(current_user.name, f"删除任务 {task_id}")
    flash("任务已删除")
    return redirect(url_for('tasks'))

@app.after_request
def set_secure_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net"
    return response

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=True)
