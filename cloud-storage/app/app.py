import os
import pathlib
import sqlite3
import functools
import datetime
import time
import unicodedata

import flask
import werkzeug.security
import werkzeug.utils

from config import Config


app = flask.Flask(__name__)
app.config.from_object(Config)

# Конфигурация ролей по умолчанию
DEFAULT_ROLES = ['admin', 'moderator', 'user']
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'

# Создаем папку для загрузок
pathlib.Path(app.config['UPLOAD_FOLDER']).mkdir(exist_ok=True)


def init_db():
    con = sqlite3.connect(app.config['DATABASE_FILE'])
    cursor = con.cursor()
    
    # Создаем таблицу ролей
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            permissions TEXT DEFAULT ''
        )
        '''
    )
    
    # Создаем таблицу пользователей с внешним ключом на роли
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role_id INTEGER DEFAULT 3,
            email TEXT UNIQUE,
            FOREIGN KEY (role_id) REFERENCES roles(id)
        )
        '''
    )

    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            download_token TEXT,
            is_public INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, filename)
        )
        '''
    )
    
    for role in DEFAULT_ROLES:
        try:
            cursor.execute('INSERT OR IGNORE INTO roles (name) VALUES (?)', (role,))
        except sqlite3.IntegrityError:
            pass
    
    try:
        admin_role_id = cursor.execute(
            'SELECT id FROM roles WHERE name = ?', ('admin',)
        ).fetchone()[0]
        cursor.execute(
            'INSERT OR IGNORE INTO users (username, password, role_id) VALUES (?, ?, ?)',
            (ADMIN_USERNAME, werkzeug.security.generate_password_hash(ADMIN_PASSWORD), admin_role_id)
        )
    except (sqlite3.IntegrityError, TypeError):
        pass
    
    con.commit()
    con.close()


@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if isinstance(value, int):
        return datetime.datetime.fromtimestamp(value).strftime(format)
    elif hasattr(value, 'strftime'):
        return value.strftime(format)
    return str(value)


def login_required(session, message: str = "Необходимо войти в систему"):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flask.flash('Необходимо войти в систему', 'warning')
                return flask.redirect(flask.url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def role_required(role_name):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in flask.session:
                flask.abort(401)
            conn = sqlite3.connect(app.config['DATABASE_FILE'])
            role = conn.execute(
                'SELECT name FROM roles WHERE id = (SELECT role_id FROM users WHERE id = ?)',
                (flask.session['user_id'],)
            ).fetchone()
            conn.close()
            if not role or role[0] != role_name:
                flask.abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


init_db()


# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if flask.request.method == 'POST':
        username = flask.request.form['username']
        password = flask.request.form['password']
        email = flask.request.form.get('email')
        
        conn = sqlite3.connect(app.config['DATABASE_FILE'])
        cursor = conn.cursor()
        try:
            role_id = cursor.execute(
                'SELECT id FROM roles WHERE name = ?', ('user',)
            ).fetchone()[0]
            
            cursor.execute(
                'INSERT INTO users (username, password, role_id, email) VALUES (?, ?, ?, ?)',
                (username, werkzeug.security.generate_password_hash(password), role_id, email)
            )
            conn.commit()
            flask.flash('Регистрация прошла успешно!', 'success')
            return flask.redirect(flask.url_for('login'))
        except sqlite3.IntegrityError:
            flask.flash('Пользователь уже существует!', 'danger')
        finally:
            conn.close()
    return flask.render_template('auth/register.html')


# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'POST':
        username = flask.request.form['username']
        password = flask.request.form['password']
        
        conn = sqlite3.connect(app.config['DATABASE_FILE'])
        cursor = conn.cursor()
        cursor.execute(
            'SELECT users.*, roles.name as role_name FROM users JOIN roles ON users.role_id = roles.id WHERE username = ?',
            (username,)
        )
        user = cursor.fetchone()
        conn.close()
        
        if user and werkzeug.security.check_password_hash(user[2], password):
            flask.session['user_id'] = user[0]
            flask.session['username'] = user[1]
            flask.session['role'] = user[5]
            flask.flash('Вход выполнен!', 'success')
            return flask.redirect(flask.url_for('user_files'))
        else:
            flask.flash('Неверный логин или пароль!', 'danger')

    return flask.render_template('auth/login.html')


# Выход
@app.route('/logout')
def logout():
    flask.session.clear()
    flask.flash('Вы вышли из системы!', 'info')
    return flask.redirect(flask.url_for('user_files'))


# Управление пользователями (админка)
@app.route('/admin/users')
@role_required('admin')
def admin_users():
    conn = sqlite3.connect(app.config['DATABASE_FILE'])
    cursor = conn.cursor()
    
    users = cursor.execute(
        '''
        SELECT users.id, users.username, roles.name as role 
        FROM users 
        JOIN roles ON users.role_id = roles.id
        '''
    ).fetchall()
    
    roles = cursor.execute('SELECT id, name FROM roles').fetchall()
    conn.close()
    
    return flask.render_template('admin/users.html', users=users, roles=roles)


# Обновление роли пользователя
@app.route('/admin/update_role', methods=['POST'])
@role_required('admin')
def update_role():
    user_id = flask.request.form.get('user_id')
    new_role_id = flask.request.form.get('role_id')
    
    if not user_id or not new_role_id:
        flask.flash('Неверные параметры', 'danger')
        return flask.redirect(flask.url_for('admin_users'))
    
    conn = sqlite3.connect(app.config['DATABASE_FILE'])
    try:
        conn.execute(
            'UPDATE users SET role_id = ? WHERE id = ?',
            (new_role_id, user_id)
        )
        conn.commit()
        flask.flash('Роль успешно обновлена', 'success')
    except sqlite3.Error as e:
        flask.flash(f'Ошибка при обновлении роли: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return flask.redirect(flask.url_for('admin_users'))


# Управление ролями
@app.route('/admin/roles')
@role_required('admin')
def manage_roles():
    conn = sqlite3.connect(app.config['DATABASE_FILE'])
    roles = conn.execute('SELECT id, name, permissions FROM roles').fetchall()
    conn.close()
    return flask.render_template('admin/roles.html', roles=roles)


# Добавление новой роли
@app.route('/admin/add_role', methods=['POST'])
@role_required('admin')
def add_role():
    role_name = flask.request.form.get('role_name')
    if not role_name:
        flask.flash('Имя роли не может быть пустым', 'danger')
        return flask.redirect(flask.url_for('manage_roles'))
    
    conn = sqlite3.connect(app.config['DATABASE_FILE'])
    try:
        conn.execute(
            'INSERT INTO roles (name) VALUES (?)',
            (role_name,)
        )
        conn.commit()
        flask.flash('Роль успешно добавлена', 'success')
    except sqlite3.IntegrityError:
        flask.flash('Роль с таким именем уже существует', 'danger')
    finally:
        conn.close()
    
    return flask.redirect(flask.url_for('manage_roles'))


def allowed_file(filename):
    x1 = '.' in filename
    x2 = filename.rsplit('.')[-1].lower()
    x3 = x2 in app.config['ALLOWED_EXTENSIONS']
    app.logger.info(f"X1: {x1}\tX2: {x2}\tX3: {x3}")

    if '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']:
        return True
    return False


def get_user_upload_folder(user_id):
    """Возвращает путь к папке пользователя для загрузки файлов"""
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
    pathlib.Path(user_folder).mkdir(exist_ok=True)
    return user_folder


@app.route('/upload', methods=['POST'])
@login_required(flask.session)
def upload_file():
    if flask.request.method == 'POST':
        if 'file' not in flask.request.files:
            flask.flash('Файл не выбран', 'danger')
            return flask.redirect(flask.url_for('user_files'))
            
        file = flask.request.files['file']
        filename = file.filename.split('\\x00')[0]

        filename = werkzeug.utils.secure_filename(filename)

        app.logger.info(f"File: {file}\t\tName: {filename}")
        if filename == '':
            flask.flash('Файл не выбран', 'danger')
            return flask.redirect(flask.url_for('user_files'))
            
        if not allowed_file(filename):
            flask.flash('Недопустимый тип файла', 'danger')
            return flask.redirect(flask.url_for('user_files'))
        
        # Проверяем, есть ли уже файл с таким именем у пользователя
        conn = sqlite3.connect(app.config['DATABASE_FILE'])
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id FROM files WHERE user_id = ? AND filename = ?',
            (flask.session['user_id'], filename)
        )
        existing_file = cursor.fetchone()
        
        if existing_file:
            conn.close()
            flask.flash('Файл с таким именем уже существует. Удалите его перед повторной загрузкой.', 'danger')
            return flask.redirect(flask.url_for('user_files'))
            
        # Получаем папку пользователя
        user_folder = get_user_upload_folder(flask.session['user_id'])
        filepath = os.path.join(user_folder, filename)

        try:
            file.save(filepath)
            
            # Сохраняем информацию о файле в базе данных
            cursor.execute(
                'INSERT INTO files (user_id, filename, filepath, is_public) VALUES (?, ?, ?, ?)',
                (flask.session['user_id'], filename, filepath, False)
            )
            conn.commit()
            conn.close()
            
            flask.flash('Файл успешно загружен!', 'success')
            return flask.redirect(flask.url_for('user_files'))
            
        except Exception as e:
            conn.rollback()
            conn.close()
            app.logger.error(f"Ошибка при загрузке файла: {str(e)}")
            flask.flash('Произошла ошибка при загрузке файла', 'danger')
            return flask.redirect(flask.url_for('user_files'))

    # return flask.render_template('files/upload.html')


@app.route('/')
def index():
    return flask.redirect(flask.url_for('user_files'))


@app.route('/files')
@login_required(flask.session)
def user_files():
    user_id = flask.session.get('user_id')
    conn = sqlite3.connect(app.config['DATABASE_FILE'])
    cursor = conn.cursor()

    cursor.execute(
        'SELECT id, filename, is_public FROM files WHERE user_id = ?',
        (user_id,)
    )
    files = cursor.fetchall()
    conn.close()

    files_list = [{
        'id': file[0],
        'filename': file[1],
        'is_public': bool(file[2])
    } for file in files]

    return flask.render_template('files/files.html', files=files_list)


@app.route('/toggle_file_access/<int:file_id>')
@login_required(flask.session)
def toggle_file_access(file_id):
    user_id = flask.session.get('user_id')
    conn = sqlite3.connect(app.config['DATABASE_FILE'])
    cursor = conn.cursor()

    cursor.execute(
        'SELECT is_public FROM files WHERE id = ? AND user_id = ?',
        (file_id, user_id)
    )
    file = cursor.fetchone()

    if file is None:
        conn.close()
        flask.flash('Файл не найден', 'error')
        return flask.redirect(flask.url_for('user_files'))

    new_access_status = 1 if file[0] == 0 else 0

    cursor.execute(
        'UPDATE files SET is_public = ? WHERE id = ?',
        (new_access_status, file_id)
    )
    conn.commit()
    conn.close()

    return flask.redirect(flask.url_for('user_files'))


@app.route('/download/<int:file_id>')
@login_required(flask.session,)
def download_user_file(file_id):
    conn = sqlite3.connect(app.config['DATABASE_FILE'])
    cursor = conn.cursor()

    # Проверяем права доступа к файлу
    cursor.execute(
        '''
        SELECT f.filename, f.filepath, f.user_id, f.is_public
        FROM files f
        WHERE f.id = ? AND (f.user_id = ? OR is_public = 1)
        ''',
        (file_id, flask.session.get('user_id'))
    )
    
    file_record = cursor.fetchone()
    conn.close()

    if not file_record:
        flask.abort(404, description="File not found or access denied")

    file_path = file_record[1]
    original_filename = file_record[0]

    if not os.path.exists(file_path):
        flask.abort(404, description="File not found")

    return flask.send_file(
        file_path,
        as_attachment=True,
        download_name=original_filename
    )


@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required(flask.session)
def delete_file(file_id):
    user_id = flask.session.get('user_id')
    conn = sqlite3.connect(app.config['DATABASE_FILE'])
    cursor = conn.cursor()

    # Получаем информацию о файле
    cursor.execute(
        'SELECT filepath, user_id FROM files WHERE id = ?',
        (file_id,)
    )
    file_info = cursor.fetchone()

    if not file_info:
        conn.close()
        flask.flash('Файл не найден', 'danger')
        return flask.redirect(flask.url_for('user_files'))

    file_path = file_info[0]
    file_owner = file_info[1]

    # Проверяем, что пользователь является владельцем файла
    if file_owner != user_id and flask.session.get('role') != 'admin':
        conn.close()
        flask.flash('Недостаточно прав для удаления файла', 'danger')
        return flask.redirect(flask.url_for('user_files'))

    try:
        # Удаляем файл из файловой системы
        if os.path.exists(file_path):
            os.unlink(file_path)

        # Удаляем запись из базы данных
        cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        flask.flash('Файл успешно удален', 'success')
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Ошибка при удалении файла: {str(e)}")
        flask.flash('Произошла ошибка при удалении файла', 'danger')
    finally:
        conn.close()

    return flask.redirect(flask.url_for('user_files'))


@app.route('/generate_download_link/<int:file_id>')
@login_required(flask.session)
def generate_download_link(file_id):
    conn = sqlite3.connect(app.config['DATABASE_FILE'])
    cursor = conn.cursor()

    # Проверяем, что файл принадлежит пользователю
    cursor.execute(
        'SELECT id, filename FROM files WHERE id = ? AND user_id = ?',
        (file_id, flask.session['user_id'])
    )
    file = cursor.fetchone()

    if file is None:
        conn.close()
        flask.flash('Файл не найден', 'error')
        return flask.redirect(flask.url_for('user_files'))

    # Генерируем уникальный токен для ссылки
    token = werkzeug.security.secrets.token_urlsafe(16)

    # Сохраняем токен в базе данных
    cursor.execute(
        'UPDATE files SET download_token = ? WHERE id = ?',
        (token, file_id)
    )
    conn.commit()
    conn.close()

    # Генерируем URL для скачивания
    download_url = flask.url_for(
        'download_with_token',
        file_id=file_id,
        token=token,
        _external=True
    )

    # if download_url.startswith('https://'):
    #     download_url = download_url[len('https://'):]
    if download_url.startswith('http://'):
        download_url = 'https://' + download_url[len('http://'):]

    flask.flash(f'Ссылка для скачивания: {download_url}', 'success')
    return flask.redirect(flask.url_for('user_files'))


@app.route('/download_with_token/<int:file_id>/<token>')
def download_with_token(file_id, token):
    conn = sqlite3.connect(app.config['DATABASE_FILE'])
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        '''
        SELECT filename, filepath, download_token, is_public
        FROM files
        WHERE id = ?
        ''',
        (file_id,)
    )
    file = cursor.fetchone()
    conn.close()

    if not file or file['download_token'] != token:
        flask.abort(404)

    if not file['is_public']:
        flask.abort(404)

    file_path = file['filepath']
    original_filename = file['filename']

    if not os.path.exists(file_path):
        flask.abort(404)

    return flask.send_file(
        file_path,
        as_attachment=True,
        download_name=original_filename
    )


def main():
    app.run(host='0.0.0.0', port=5000, debug=True)


if __name__ == "__main__":
    main()