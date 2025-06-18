import os
import dotenv
import pathlib

dotenv.load_dotenv()


class Config:
    # Основные настройки
    SECRET_KEY = os.getenv('SECRET_KEY', 'where_is_the_key')
    DATABASE_FILE = 'database.db'
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{DATABASE_FILE}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Настройки загрузки файлов
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar', '7z'}
    # Максимальный лимит загрузки 64 MB
    MAX_CONTENT_LENGTH = 64 * 1024 * 1024
    
    # Настрокйи безопасности
    SESSION_COOKIE_HTTPONLY = True
    # True если HTTPS
    SESSION_COOKIE_SECURURE = False
    REMEMBER_COOKIE_HTTPONLY = True