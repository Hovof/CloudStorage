FROM nginx:latest

# Удаляем стандартный конфигурационный файл Nginx
RUN rm /etc/nginx/conf.d/default.conf

# Копируем новый конфигурационный файл Nginx
COPY nginx.conf /etc/nginx/conf.d/

# Копируем самоподписанные сертификаты
COPY certs/nginx-selfsigned.crt /etc/nginx/certs/
COPY certs/nginx-selfsigned.key /etc/nginx/certs/