# Используем официальный образ Python
FROM python:3.9

# Устанавливаем рабочий каталог
WORKDIR /app

# Копируем требования и устанавливаем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код приложения
COPY . .

# Открываем порт, на котором будет работать приложение
EXPOSE 5000

RUN chown -R www-data:www-data /app
RUN chmod -R 700 /app

USER www-data

# Запускаем приложение
CMD ["python", "app.py"]