# =================================================================
# IMPORT LIBRARY YANG DIBUTUHKAN
# =================================================================
import os
import hashlib
from flask import Flask, request, render_template, redirect, url_for, flash, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from blockchain import Blockchain
from functools import wraps
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

# =================================================================
# INISIALISASI DAN KONFIGURASI APLIKASI
# =================================================================
app = Flask(__name__)
app.secret_key = 'ganti-dengan-kunci-rahasia-yang-sangat-aman-dan-unik'

# --- Konfigurasi untuk Flask-Mail ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'emailanda@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'password_aplikasi_anda')
app.config['MAIL_DEFAULT_SENDER'] = ('SISFOARSIP', app.config['MAIL_USERNAME'])

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# --- Konfigurasi Folder Upload ---
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

blockchain = Blockchain()

# =================================================================
# FUNGSI FILTER KUSTOM UNTUK TEMPLATE JINJA2
# =================================================================
@app.template_filter('strftime')
def _jinja2_filter_datetime(timestamp, fmt='%Y-%m-%d %H:%M:%S'):
    """Memformat timestamp UNIX menjadi string tanggal yang mudah dibaca."""
    if timestamp is None:
        return "N/A"
    dt_object = datetime.fromtimestamp(timestamp)
    return dt_object.strftime(fmt)

# =================================================================
# DECORATOR UNTUK OTENTIKASI DAN HAK AKSES
# =================================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Anda harus login untuk mengakses halaman ini.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def roles_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') not in allowed_roles:
                flash(f'Hanya peran {", ".join(allowed_roles)} yang dapat mengakses halaman ini.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# =================================================================
# FUNGSI BANTU (HELPERS)
# =================================================================
def get_all_item_states():
    """Membaca seluruh blockchain untuk mendapatkan status terakhir dari setiap item."""
    item_states = {}
    all_blocks = blockchain.chain
    for block in all_blocks:
        for data_content in block.get('data', {}).values():
            if not isinstance(data_content, dict):
                continue

            item_name = None
            item_type = data_content.get('type')

            if item_type in ['folder_creation', 'folder_rename']:
                item_name = data_content.get('folder_name') or data_content.get('new_folder_name')
            elif item_type == 'file_upload':
                item_name = data_content.get('filename')
            elif item_type in ['item_trashed', 'item_restored', 'access_update']:
                item_name = data_content.get('item_name')

            if not item_name:
                continue

            if item_type in ['folder_creation', 'file_upload']:
                item_states.setdefault(item_name, {'data': {}})['status'] = 'active'
                item_states[item_name]['data'].update(data_content)
                item_states[item_name]['timestamp'] = block['timestamp']
            elif item_type == 'item_trashed':
                if item_name in item_states:
                    item_states[item_name]['status'] = 'trashed'
                    item_states[item_name]['trashed_info'] = data_content
                    item_states[item_name]['trashed_info']['timestamp'] = block['timestamp']
            elif item_type == 'item_restored':
                 if item_name in item_states:
                    item_states[item_name]['status'] = 'active'
            elif item_type == 'access_update':
                if item_name in item_states:
                    if data_content['item_type'] == 'folder':
                        item_states[item_name]['data']['allowed_dosen_folder'] = data_content['new_allowed_dosen']
                    elif data_content['item_type'] == 'file':
                        item_states[item_name]['data']['allowed_dosen_file'] = data_content['new_allowed_dosen']

    return item_states

def has_file_access(file_record):
    """Memeriksa apakah pengguna saat ini memiliki akses ke file."""
    if not file_record:
        return False
    
    is_public = file_record.get('file_access') == 'publik'
    is_admin = session['role'] == 'admin'
    is_allowed_dosen = session['role'] == 'dosen' and session['email'] in file_record.get('allowed_dosen_file', [])
    is_own_private_file = session['role'] == 'mahasiswa' and session['email'] == file_record.get('uploader_email') and not is_public

    return is_admin or is_public or is_allowed_dosen or is_own_private_file

# =================================================================
# RUTE OTENTIKASI
# =================================================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        if not all([email, password, role]):
            flash('Semua kolom harus diisi!', 'danger')
            return redirect(url_for('register'))
        if blockchain.find_user_by_email(email):
            flash('Email sudah terdaftar!', 'warning')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user_data = {'email': email, 'password_hash': hashed_password, 'role': role, 'type': 'user_registration'}
        last_block = blockchain.last_block
        blockchain.add_user_data_to_block(last_block, user_data)
        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not all([email, password]):
            flash('Email dan password tidak boleh kosong!', 'danger')
            return redirect(url_for('login'))
        user_data = blockchain.find_user_by_email(email)
        if user_data and check_password_hash(user_data['password_hash'], password):
            session['logged_in'] = True
            session['email'] = user_data['email']
            session['role'] = user_data.get('role', 'mahasiswa')
            flash(f"Selamat datang kembali, {session['email']}!", 'success')
            if session['role'] == 'admin': return redirect(url_for('admin_dashboard'))
            elif session['role'] == 'dosen': return redirect(url_for('dosen_dashboard'))
            else: return redirect(url_for('mahasiswa_dashboard'))
        else:
            flash('Email atau password salah!', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Anda telah berhasil logout.', 'info')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user_data = blockchain.find_user_by_email(email)
        if not user_data:
            flash('Email tidak terdaftar di sistem kami.', 'warning')
            return redirect(url_for('forgot_password'))
        token = serializer.dumps(email, salt='password-reset-salt')
        reset_url = url_for('reset_password', token=token, _external=True)
        msg = Message('Reset Password - SISFOARSIP', recipients=[email])
        msg.body = f"Klik link berikut untuk mereset password Anda (berlaku 1 jam):\n\n{reset_url}"
        try:
            mail.send(msg)
            flash('Link reset password telah dikirim ke email Anda.', 'success')
        except Exception as e:
            flash(f'Gagal mengirim email. Coba lagi nanti. Error: {e}', 'danger')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        flash('Link reset password tidak valid atau sudah kedaluwarsa.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if new_password != confirm_password or not new_password:
            flash('Password baru dan konfirmasi tidak cocok atau kosong.', 'danger')
            return redirect(url_for('reset_password', token=token))
        user_data = blockchain.find_user_by_email(email)
        if not user_data:
            flash('Pengguna tidak ditemukan.', 'danger')
            return redirect(url_for('login'))
        new_hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        update_data = {'email': email, 'password_hash': new_hashed_password, 'role': user_data.get('role'), 'type': 'user_update'}
        previous_block = blockchain.last_block
        previous_hash = blockchain.hash(previous_block)
        new_block = blockchain.new_block(12345, previous_hash)
        blockchain.add_user_data_to_block(new_block, update_data)
        flash('Password Anda telah berhasil direset. Silakan login.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

# =================================================================
# RUTE UPLOAD DAN MANAJEMEN FOLDER
# =================================================================
@app.route('/upload', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def upload():
    upload_path = app.config['UPLOAD_FOLDER']
    existing_folders = [d for d in os.listdir(upload_path) if os.path.isdir(os.path.join(upload_path, d))] if os.path.exists(upload_path) else []
    dosen_users = list({d['email']: d for d in [data for block in blockchain.chain for data in block.get('data', {}).values() if isinstance(data, dict) and data.get('type') == 'user_registration' and data.get('role') == 'dosen']}.values())
    
    if request.method == 'POST':
        folder_name = request.form.get('folder_name')
        letter_type = request.form.get('letter_type')
        file_access = request.form.get('file_access')
        allowed_dosen_file = request.form.getlist('allowed_dosen_file')
        file = request.files.get('file')
        is_new_folder = request.form.get('is_new_folder') == 'true'
        folder_access = request.form.get('folder_access')
        allowed_dosen_folder = request.form.getlist('allowed_dosen_folder')

        if not all([folder_name, letter_type, file_access, file]) or file.filename == '':
            flash('Folder, Jenis Surat, Hak Akses File, dan File harus diisi.', 'danger')
            return redirect(request.url)
            
        secure_folder_name = secure_filename(folder_name)
        secure_file_name = secure_filename(file.filename)
        target_folder_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_folder_name)
        if not os.path.exists(target_folder_path):
            os.makedirs(target_folder_path)
        
        file_path = os.path.join(target_folder_path, secure_file_name)
        file_content = file.read()
        file_hash = hashlib.sha256(file_content).hexdigest()
        with open(file_path, 'wb') as f:
            f.write(file_content)
        file.seek(0)
        
        file_data = {
            'uploader_email': session['email'], 'filename': secure_file_name, 'folder': secure_folder_name,
            'letter_type': letter_type, 'file_path': file_path, 'type': 'file_upload', 'file_hash': file_hash,
            'file_access': file_access, 'allowed_dosen_file': allowed_dosen_file if file_access == 'privat' else [],
        }

        if is_new_folder:
            file_data['is_new_folder'] = True
            file_data['folder_access'] = folder_access
            file_data['allowed_dosen_folder'] = allowed_dosen_folder if folder_access == 'privat' else []
        
        previous_block = blockchain.last_block
        previous_hash = blockchain.hash(previous_block)
        new_block = blockchain.new_block(12345, previous_hash)
        blockchain.add_user_data_to_block(new_block, file_data)
        
        flash(f'File "{secure_file_name}" berhasil diunggah dan dicatat di Blok #{new_block["index"]}.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('upload.html', existing_folders=existing_folders, dosen_list=dosen_users)

@app.route('/mahasiswa/upload', methods=['GET', 'POST'])
@login_required
@roles_required('mahasiswa')
def mahasiswa_upload():
    upload_path = app.config['UPLOAD_FOLDER']
    existing_folders = [d for d in os.listdir(upload_path) if os.path.isdir(os.path.join(upload_path, d))] if os.path.exists(upload_path) else []
    dosen_users = list({d['email']: d for d in [data for block in blockchain.chain for data in block.get('data', {}).values() if isinstance(data, dict) and data.get('type') == 'user_registration' and data.get('role') == 'dosen']}.values())
    
    if request.method == 'POST':
        folder_name = request.form.get('folder_name')
        file_access = request.form.get('access_level')
        allowed_dosen = request.form.getlist('allowed_dosen')
        file = request.files.get('file')
        letter_type = 'surat_masuk'

        if not all([folder_name, file_access, file]) or file.filename == '':
            flash('Folder tujuan, hak akses, dan file wajib diisi.', 'danger')
            return redirect(request.url)

        secure_folder_name = secure_filename(folder_name)
        secure_file_name = secure_filename(file.filename)
        target_folder_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_folder_name)
        if not os.path.exists(target_folder_path):
            flash(f'Error: Folder "{secure_folder_name}" tidak ditemukan.', 'danger')
            return redirect(request.url)
        
        file_path = os.path.join(target_folder_path, secure_file_name)
        file_content = file.read()
        file_hash = hashlib.sha256(file_content).hexdigest()
        with open(file_path, 'wb') as f:
            f.write(file_content)
        file.seek(0)

        file_data = {
            'uploader_email': session['email'], 'filename': secure_file_name, 'folder': secure_folder_name,
            'letter_type': letter_type, 'file_path': file_path, 'type': 'file_upload', 'file_hash': file_hash,
            'file_access': file_access, 'allowed_dosen_file': allowed_dosen if file_access == 'privat' else []
        }

        previous_block = blockchain.last_block
        previous_hash = blockchain.hash(previous_block)
        new_block = blockchain.new_block(12345, previous_hash)
        blockchain.add_user_data_to_block(new_block, file_data)

        flash(f'File "{secure_file_name}" berhasil diunggah dan dicatat di Blok #{new_block["index"]}.', 'success')
        return redirect(url_for('mahasiswa_dashboard'))
    
    return render_template('mahasiswa_upload.html', existing_folders=existing_folders, dosen_list=dosen_users)

@app.route('/create_folder', methods=['POST'])
@login_required
@roles_required('admin', 'mahasiswa')
def create_folder():
    folder_name = request.form.get('new_folder_name')
    folder_access = request.form.get('folder_access')
    if not folder_name or not folder_access:
        flash('Nama folder dan hak akses wajib diisi.', 'danger')
        return redirect(url_for('view_folders'))
    secure_folder_name = secure_filename(folder_name)
    target_folder_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_folder_name)
    if os.path.exists(target_folder_path):
        flash(f'Folder dengan nama "{secure_folder_name}" sudah ada.', 'warning')
    else:
        try:
            os.makedirs(target_folder_path)
            folder_data = {
                'creator_email': session['email'], 'folder_name': secure_folder_name,
                'folder_access': folder_access, 'type': 'folder_creation'
            }
            previous_block = blockchain.last_block
            proof = 12345
            previous_hash = blockchain.hash(previous_block)
            new_block = blockchain.new_block(proof, previous_hash)
            blockchain.add_user_data_to_block(new_block, folder_data)
            flash(f'Folder "{secure_folder_name}" dengan hak akses "{folder_access}" berhasil dibuat dan dicatat di Blok #{new_block["index"]}.', 'success')
        except Exception as e:
            flash(f'Gagal membuat folder: {e}', 'danger')
    return redirect(url_for('view_folders'))

@app.route('/edit_folder', methods=['POST'])
@login_required
@roles_required('admin')
def edit_folder():
    old_name = request.form.get('old_folder_name')
    new_name = request.form.get('new_folder_name')
    if not old_name or not new_name:
        flash('Nama folder lama dan baru tidak boleh kosong.', 'danger')
        return redirect(url_for('view_folders'))
    if old_name == new_name:
        flash('Nama folder baru tidak boleh sama dengan nama lama.', 'warning')
        return redirect(url_for('view_folders'))
    secure_old_name = secure_filename(old_name)
    secure_new_name = secure_filename(new_name)
    old_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_old_name)
    new_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_new_name)
    if not os.path.exists(old_path):
        flash(f'Error: Folder sumber "{secure_old_name}" tidak ditemukan.', 'danger')
        return redirect(url_for('view_folders'))
    if os.path.exists(new_path):
        flash(f'Error: Folder dengan nama "{secure_new_name}" sudah ada.', 'danger')
        return redirect(url_for('view_folders'))
    try:
        os.rename(old_path, new_path)
        rename_data = {
            'editor_email': session['email'],
            'old_folder_name': secure_old_name,
            'new_folder_name': secure_new_name,
            'type': 'folder_rename'
        }
        previous_block = blockchain.last_block
        proof = 12345
        previous_hash = blockchain.hash(previous_block)
        new_block = blockchain.new_block(proof, previous_hash)
        blockchain.add_user_data_to_block(new_block, rename_data)
        flash(f'Folder "{secure_old_name}" berhasil diubah menjadi "{secure_new_name}".', 'success')
    except Exception as e:
        flash(f'Gagal mengubah nama folder: {e}', 'danger')
    return redirect(url_for('view_folders'))

# =================================================================
# RUTE UNTUK MELIHAT FILE, PENCARIAN, DAN VALIDASI
# =================================================================
@app.route('/folders')
@login_required
@roles_required('admin', 'dosen', 'mahasiswa')
def view_folders():
    item_states = get_all_item_states()
    active_folders = set()
    for name, state in item_states.items():
        if state['status'] == 'active' and state['data'].get('type') in ['folder_creation', 'file_upload']:
            active_folders.add(state['data'].get('folder_name') or state['data'].get('folder'))
    sorted_folders = sorted(list(active_folders))
    return render_template('view_folders.html', folders=sorted_folders)

@app.route('/folder/<folder_name>')
@login_required
@roles_required('admin', 'dosen', 'mahasiswa')
def view_folder_content(folder_name):
    item_states = get_all_item_states()
    files_in_folder = []
    for name, state in item_states.items():
        if state['status'] == 'active' and state['data'].get('type') == 'file_upload' and state['data'].get('folder') == folder_name:
            if has_file_access(state['data']):
                file_info = state['data'].copy()
                file_info['timestamp'] = state.get('timestamp')
                files_in_folder.append(file_info)
                
    sorted_files = sorted(files_in_folder, key=lambda x: x.get('timestamp', 0), reverse=True)
    return render_template('view_files.html', files=sorted_files, folder_name=folder_name)

@app.route('/view/<path:filepath>')
@login_required
def view_file(filepath):
    try:
        directory, filename = os.path.split(filepath)
        return send_from_directory(directory, filename)
    except Exception as e:
        flash(f'Tidak dapat menemukan file: {e}', 'danger')
        return redirect(url_for('view_folders'))

@app.route('/download/<path:filepath>')
@login_required
def download_file(filepath):
    try:
        directory, filename = os.path.split(filepath)
        return send_from_directory(directory, filename, as_attachment=True)
    except Exception as e:
        flash(f'Tidak dapat menemukan file: {e}', 'danger')
        return redirect(url_for('view_folders'))

@app.route('/search', methods=['GET', 'POST'])
@login_required
@roles_required('admin', 'dosen', 'mahasiswa')
def search_files():
    if request.method == 'POST':
        query = request.form.get('query', '').lower()
        if not query:
            flash('Silakan masukkan kata kunci pencarian.', 'warning')
            return render_template('search_files.html')
        search_results = []
        item_states = get_all_item_states()
        for name, state in item_states.items():
            if state['status'] == 'active' and state['data'].get('type') == 'file_upload':
                if has_file_access(state['data']):
                    match = any(query in str(state['data'].get(key, '')).lower() for key in ['filename', 'folder', 'uploader_email'])
                    if match:
                        search_results.append(state['data'])
        sorted_results = sorted(search_results, key=lambda x: x.get('timestamp', 0), reverse=True)
        return render_template('search_files.html', results=sorted_results, query=query)
    return render_template('search_files.html')

@app.route('/admin/users')
@login_required
@roles_required('admin')
def manage_users():
    # Mengambil semua event pengguna BERSAMA DENGAN TIMESTAMP dari bloknya
    user_events = []
    for block in blockchain.chain:
        for data in block.get('data', {}).values():
            if isinstance(data, dict) and data.get('type') in ['user_registration', 'user_deactivation']:
                # Salin data event dan tambahkan timestamp dari blok
                event_with_timestamp = data.copy()
                event_with_timestamp['timestamp'] = block.get('timestamp')
                user_events.append(event_with_timestamp)

    active_users = {}
    deactivated_users = set()

    # Memproses event untuk menentukan status terakhir setiap pengguna
    for event in user_events:
        if event['type'] == 'user_registration':
            email = event.get('email')
            if email and email not in deactivated_users:
                # Simpan event yang sudah lengkap dengan timestamp
                active_users[email] = event
        elif event['type'] == 'user_deactivation':
            email = event.get('deleted_user_email')
            if email:
                deactivated_users.add(email)
                if email in active_users:
                    del active_users[email]

    # Mengurutkan pengguna aktif berdasarkan timestamp registrasi
    sorted_users = sorted(active_users.values(), key=lambda x: x.get('timestamp', 0), reverse=True)
    
    return render_template('manage_users.html', users=sorted_users)

@app.route('/admin/edit_user', methods=['POST'])
@login_required
@roles_required('admin')
def edit_user():
    email = request.form.get('user_email')
    new_role = request.form.get('new_role')

    if not email or not new_role:
        flash('Informasi tidak lengkap untuk mengubah peran pengguna.', 'danger')
        return redirect(url_for('manage_users'))

    user_data = blockchain.find_user_by_email(email)
    if not user_data:
        flash('Pengguna tidak ditemukan.', 'danger')
        return redirect(url_for('manage_users'))

    update_data = {
        'editor_email': session['email'],
        'email': email,
        'password_hash': user_data.get('password_hash'),
        'role': new_role,
        'type': 'user_update'
    }

    previous_block = blockchain.last_block
    previous_hash = blockchain.hash(previous_block)
    new_block = blockchain.new_block(12345, previous_hash)
    blockchain.add_user_data_to_block(new_block, update_data)

    flash(f'Peran untuk pengguna {email} telah berhasil diubah menjadi {new_role}.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/validate', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def validate_file():
    if request.method == 'POST':
        file = request.files.get('file_to_validate')
        if not file or file.filename == '':
            flash('Silakan pilih file untuk divalidasi.', 'warning')
            return redirect(url_for('validate_file'))
        file_content = file.read()
        uploaded_file_hash = hashlib.sha256(file_content).hexdigest()
        validation_result = {'filename': file.filename, 'file_hash': uploaded_file_hash, 'is_valid': False}
        for block in reversed(blockchain.chain):
            for data_content in block.get('data', {}).values():
                if isinstance(data_content, dict) and data_content.get('type') == 'file_upload' and data_content.get('filename') == file.filename and data_content.get('file_hash') == uploaded_file_hash:
                    validation_result.update({'is_valid': True, 'block_index': block['index'], 'timestamp': block['timestamp'], 'uploader_email': data_content['uploader_email'], 'folder': data_content['folder']})
                    return render_template('validate_file.html', validation_result=validation_result)
        return render_template('validate_file.html', validation_result=validation_result)
    return render_template('validate_file.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if not all([old_password, new_password, confirm_password]):
            flash('Semua kolom password harus diisi.', 'danger')
            return redirect(url_for('profile'))
        if new_password != confirm_password:
            flash('Password baru dan konfirmasi tidak cocok.', 'danger')
            return redirect(url_for('profile'))
        user_data = blockchain.find_user_by_email(session['email'])
        if not user_data or not check_password_hash(user_data['password_hash'], old_password):
            flash('Password lama yang Anda masukkan salah.', 'danger')
            return redirect(url_for('profile'))
        new_hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        update_data = {'email': session['email'], 'password_hash': new_hashed_password, 'role': session['role'], 'type': 'user_update'}
        previous_block = blockchain.last_block
        previous_hash = blockchain.hash(previous_block)
        new_block = blockchain.new_block(12345, previous_hash)
        blockchain.add_user_data_to_block(new_block, update_data)
        flash('Password Anda telah berhasil diperbarui.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html')

@app.route('/blockchain')
@login_required
@roles_required('admin')
def view_blockchain():
    return render_template('view_blockchain.html', chain=blockchain.chain)

@app.route('/dosen/blockchain')
@login_required
@roles_required('dosen')
def dosen_view_blockchain():
    return render_template('dosen_view_blockchain.html', chain=blockchain.chain)

@app.route('/mahasiswa/blockchain')
@login_required
@roles_required('mahasiswa')
def mahasiswa_view_blockchain():
    return render_template('dosen_view_blockchain.html', chain=blockchain.chain)

# =================================================================
# RUTE-RUTE BARU UNTUK KELOLA AKSES
# =================================================================
@app.route('/admin/manage-access')
@login_required
@roles_required('admin')
def manage_access():
    item_states = get_all_item_states()
    private_folders = {}
    private_files = []
    
    for name, state in item_states.items():
        if state['status'] == 'active':
            if state['data'].get('type') == 'folder_creation' and state['data'].get('folder_access') == 'privat':
                private_folders[name] = state['data']
            elif state['data'].get('type') == 'file_upload' and state['data'].get('file_access') == 'privat':
                private_files.append(state['data'])

    return render_template('manage_access.html', private_folders=private_folders, private_files=private_files)

@app.route('/admin/edit-access/<item_type>/<item_name>')
@login_required
@roles_required('admin')
def edit_access(item_type, item_name):
    all_dosen = list({d['email']: d for d in [data for block in blockchain.chain for data in block.get('data', {}).values() if isinstance(data, dict) and data.get('type') == 'user_registration' and data.get('role') == 'dosen']}.values())
    
    item_states = get_all_item_states()
    current_access = []
    
    if item_name in item_states:
        item_data = item_states[item_name]['data']
        if item_type == 'folder':
            current_access = item_data.get('allowed_dosen_folder', [])
        elif item_type == 'file':
            current_access = item_data.get('allowed_dosen_file', [])

    return render_template('edit_access.html', item_type=item_type, item_name=item_name, all_dosen=all_dosen, current_access=current_access)

@app.route('/admin/save-access', methods=['POST'])
@login_required
@roles_required('admin')
def save_access():
    item_type = request.form.get('item_type')
    item_name = request.form.get('item_name')
    allowed_dosen = request.form.getlist('allowed_dosen')

    access_update_data = {
        'editor_email': session['email'],
        'item_type': item_type,
        'item_name': item_name,
        'new_allowed_dosen': allowed_dosen,
        'type': 'access_update'
    }

    previous_block = blockchain.last_block
    previous_hash = blockchain.hash(previous_block)
    new_block = blockchain.new_block(12345, previous_hash)
    blockchain.add_user_data_to_block(new_block, access_update_data)

    flash(f'Hak akses untuk {item_type} "{item_name}" telah berhasil diperbarui.', 'success')
    return redirect(url_for('manage_access'))

# =================================================================
# RUTE UNTUK FITUR SAMPAH
# =================================================================
@app.route('/move_to_trash/<item_type>/<item_name>')
@login_required
@roles_required('admin')
def move_to_trash(item_type, item_name):
    trash_data = {'trasher_email': session['email'], 'item_type': item_type, 'item_name': item_name, 'type': 'item_trashed'}
    previous_block = blockchain.last_block
    previous_hash = blockchain.hash(previous_block)
    new_block = blockchain.new_block(12345, previous_hash)
    blockchain.add_user_data_to_block(new_block, trash_data)
    flash(f'{item_type.capitalize()} "{item_name}" telah dipindahkan ke sampah.', 'success')
    return redirect(request.referrer or url_for('view_folders'))

@app.route('/trash')
@login_required
@roles_required('admin')
def trash_bin():
    item_states = get_all_item_states()
    trashed_items = [state['trashed_info'] for name, state in item_states.items() if state['status'] == 'trashed']
    sorted_items = sorted(trashed_items, key=lambda x: x['timestamp'], reverse=True)
    return render_template('trash.html', trashed_items=sorted_items)

# =================================================================
# RUTE DASHBOARD
# =================================================================
from datetime import datetime # Pastikan ini ada di bagian atas file Anda

@app.route('/admin/dashboard', methods=['GET']) # Ubah menjadi GET saja
@login_required
@roles_required('admin')
def admin_dashboard():
    show_view = request.args.get('show', 'main')
    item_states = get_all_item_states()
    active_files = []
    total_files = 0
    shared_files = 0
    active_folders = set()

    for name, state in item_states.items():
        if state['status'] == 'active':
            if state['data'].get('type') == 'file_upload':
                total_files += 1
                file_info = state['data'].copy()
                file_info['timestamp'] = state.get('timestamp')
                active_files.append(file_info)
                if file_info.get('file_access') == 'privat' and file_info.get('allowed_dosen_file'):
                    shared_files += 1
            if state['data'].get('type') in ['folder_creation', 'file_upload']:
                folder_name = state['data'].get('folder_name') or state['data'].get('folder')
                if folder_name:
                    active_folders.add(folder_name)

    # Menyiapkan data untuk filter dropdown
    all_uploaders = sorted(list(set(f.get('uploader_email') for f in active_files if f.get('uploader_email'))))
    all_years = sorted(list(set(datetime.fromtimestamp(f.get('timestamp', 0)).year for f in active_files if f.get('timestamp'))), reverse=True)
    
    recent_files = sorted(active_files, key=lambda x: x.get('timestamp', 0), reverse=True)[:5]
    sorted_folders = sorted(list(active_folders))
    stats = {'total_files': total_files, 'shared_files': shared_files, 'downloads': 456, 'activities': 24 }

    search_query = None
    search_results = None

    if show_view == 'search':
        search_query = request.args.get('query', '')
        selected_letter_type = request.args.get('letter_type', 'all')
        selected_year = request.args.get('year', 'all')
        selected_uploader = request.args.get('uploader', 'all')
        sort_by = request.args.get('sort_by', 'timestamp')
        sort_order = request.args.get('sort_order', 'desc')

        results = list(active_files) # Salin daftar untuk difilter

        # Terapkan filter
        if search_query:
            results = [f for f in results if search_query.lower() in f.get('filename', '').lower()]
        if selected_letter_type != 'all':
            results = [f for f in results if f.get('letter_type') == selected_letter_type]
        if selected_year != 'all':
            results = [f for f in results if datetime.fromtimestamp(f.get('timestamp', 0)).year == int(selected_year)]
        if selected_uploader != 'all':
            results = [f for f in results if f.get('uploader_email') == selected_uploader]

        # Terapkan pengurutan
        reverse_order = (sort_order == 'desc')
        if sort_by == 'filename':
            results.sort(key=lambda x: x.get('filename', '').lower(), reverse=reverse_order)
        else: # Default: sort by timestamp
            results.sort(key=lambda x: x.get('timestamp', 0), reverse=reverse_order)
            
        search_results = results

    return render_template('admin_dashboard.html', 
                           recent_files=recent_files, stats=stats, folders=sorted_folders,
                           show_view=show_view, search_query=search_query, search_results=search_results,
                           all_uploaders=all_uploaders, all_years=all_years)

@app.route('/dosen/dashboard', methods=['GET']) # Ubah menjadi GET saja
@login_required
@roles_required('dosen')
def dosen_dashboard():
    show_view = request.args.get('show', 'main')
    item_states = get_all_item_states()
    accessible_files = []
    active_folders = set()

    for name, state in item_states.items():
        if state['status'] == 'active':
            if state['data'].get('type') == 'file_upload' and has_file_access(state['data']):
                file_info = state['data'].copy()
                file_info['timestamp'] = state.get('timestamp')
                accessible_files.append(file_info)
            if state['data'].get('type') in ['folder_creation', 'file_upload']:
                folder_name = state['data'].get('folder_name') or state['data'].get('folder')
                if folder_name:
                    active_folders.add(folder_name)
    
    # Menyiapkan data untuk filter dropdown
    all_uploaders = sorted(list(set(f.get('uploader_email') for f in accessible_files if f.get('uploader_email'))))
    all_years = sorted(list(set(datetime.fromtimestamp(f.get('timestamp', 0)).year for f in accessible_files if f.get('timestamp'))), reverse=True)

    recent_files = sorted(accessible_files, key=lambda x: x.get('timestamp', 0), reverse=True)[:5]
    sorted_folders = sorted(list(active_folders))
    stats = {
        'accessible_files': len(accessible_files),
        'shared_to_me': sum(1 for f in accessible_files if f.get('file_access') == 'privat' and session.get('email') in f.get('allowed_dosen_file', [])),
        'activities': len(accessible_files) + len(sorted_folders)
    }

    search_query = None
    search_results = None

    if show_view == 'search':
        search_query = request.args.get('query', '')
        selected_letter_type = request.args.get('letter_type', 'all')
        selected_year = request.args.get('year', 'all')
        selected_uploader = request.args.get('uploader', 'all')
        sort_by = request.args.get('sort_by', 'timestamp')
        sort_order = request.args.get('sort_order', 'desc')

        results = list(accessible_files) # Salin daftar untuk difilter

        # Terapkan filter
        if search_query:
            results = [f for f in results if search_query.lower() in f.get('filename', '').lower()]
        if selected_letter_type != 'all':
            results = [f for f in results if f.get('letter_type') == selected_letter_type]
        if selected_year != 'all':
            results = [f for f in results if datetime.fromtimestamp(f.get('timestamp', 0)).year == int(selected_year)]
        if selected_uploader != 'all':
            results = [f for f in results if f.get('uploader_email') == selected_uploader]

        # Terapkan pengurutan
        reverse_order = (sort_order == 'desc')
        if sort_by == 'filename':
            results.sort(key=lambda x: x.get('filename', '').lower(), reverse=reverse_order)
        else:
            results.sort(key=lambda x: x.get('timestamp', 0), reverse=reverse_order)
            
        search_results = results

    return render_template('dosen_dashboard.html', 
                           recent_files=recent_files, stats=stats, folders=sorted_folders,
                           show_view=show_view, search_query=search_query, search_results=search_results,
                           all_uploaders=all_uploaders, all_years=all_years)
    
@app.route('/mahasiswa/dashboard')
@login_required
@roles_required('mahasiswa')
def mahasiswa_dashboard():
    # Menerima parameter 'show' dari URL, default-nya 'main'
    show_view = request.args.get('show', 'main')

    item_states = get_all_item_states()
    accessible_files = []
    my_uploads = 0
    active_folders = set()

    for name, state in item_states.items():
        if state['status'] == 'active':
            if state['data'].get('type') == 'file_upload':
                if state['data'].get('uploader_email') == session['email']:
                    my_uploads += 1
                
                if has_file_access(state['data']):
                    file_info = state['data'].copy()
                    file_info['timestamp'] = state.get('timestamp')
                    accessible_files.append(file_info)

            if state['data'].get('type') in ['folder_creation', 'file_upload']:
                folder_name = state['data'].get('folder_name') or state['data'].get('folder')
                if folder_name:
                    active_folders.add(folder_name)
    
    dosen_users = list({d['email']: d for d in [data for block in blockchain.chain for data in block.get('data', {}).values() if isinstance(data, dict) and data.get('type') == 'user_registration' and data.get('role') == 'dosen']}.values())
    recent_files = sorted(accessible_files, key=lambda x: x.get('timestamp', 0), reverse=True)[:5]
    sorted_folders = sorted(list(active_folders))

    stats = {
        'my_uploads': my_uploads,
        'accessible_files': len(accessible_files),
        'activities': len(accessible_files) + len(sorted_folders)
    }
    
    # Mengirim variabel show_view ke template
    return render_template('mahasiswa_dashboard.html', 
                           recent_files=recent_files, 
                           stats=stats, 
                           folders=sorted_folders, 
                           dosen_list=dosen_users,
                           existing_folders=sorted_folders,
                           show_view=show_view)
    
    
# =================================================================
# RUTE-RUTE BARU UNTUK KELOLA AKSES MAHASISWA
# =================================================================
@app.route('/mahasiswa/edit-access/<filename>', methods=['GET', 'POST'])
@login_required
@roles_required('mahasiswa')
def mahasiswa_edit_access(filename):
    item_states = get_all_item_states()
    
    # Keamanan: Pastikan file ada dan milik mahasiswa yang login
    if filename not in item_states or item_states[filename]['data'].get('uploader_email') != session['email']:
        flash('Anda tidak memiliki izin untuk mengedit akses file ini.', 'danger')
        return redirect(url_for('view_folders'))

    file_data = item_states[filename]['data']

    if request.method == 'POST':
        allowed_dosen = request.form.getlist('allowed_dosen')
        
        access_update_data = {
            'editor_email': session['email'],
            'item_type': 'file',
            'item_name': filename,
            'new_allowed_dosen': allowed_dosen,
            'type': 'access_update'
        }

        previous_block = blockchain.last_block
        previous_hash = blockchain.hash(previous_block)
        new_block = blockchain.new_block(12345, previous_hash)
        blockchain.add_user_data_to_block(new_block, access_update_data)

        flash(f'Hak akses untuk file "{filename}" telah berhasil diperbarui.', 'success')
        return redirect(url_for('view_folder_content', folder_name=file_data['folder']))

    # Handle GET request
    all_dosen = list({d['email']: d for d in [data for block in blockchain.chain for data in block.get('data', {}).values() if isinstance(data, dict) and data.get('type') == 'user_registration' and data.get('role') == 'dosen']}.values())
    current_access = file_data.get('allowed_dosen_file', [])
    
    return render_template('mahasiswa_edit_access.html', 
                           filename=filename, 
                           all_dosen=all_dosen, 
                           current_access=current_access)
# =================================================================
# rute hapus pengguna
# =================================================================
@app.route('/admin/delete_user/<email>')
@login_required
@roles_required('admin')
def delete_user(email):
    # Keamanan: Admin tidak bisa menghapus akunnya sendiri
    if email == session['email']:
        flash('Anda tidak dapat menghapus akun Anda sendiri.', 'danger')
        return redirect(url_for('manage_users'))

    # Catat event penghapusan pengguna di blockchain
    delete_data = {
        'deleter_email': session['email'],
        'deleted_user_email': email,
        'type': 'user_deactivation'
    }
    previous_block = blockchain.last_block
    previous_hash = blockchain.hash(previous_block)
    new_block = blockchain.new_block(12345, previous_hash)
    blockchain.add_user_data_to_block(new_block, delete_data)

    flash(f'Pengguna {email} telah berhasil dinonaktifkan.', 'success')
    return redirect(url_for('manage_users'))
# =================================================================
# MENJALANKAN APLIKASI
# =================================================================
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
