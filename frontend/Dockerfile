# frontend/Dockerfile
FROM nginx:alpine

# Удаляем дефолтный конфиг Nginx
RUN rm /etc/nginx/conf.d/default.conf

# Копируем наш HTML-файл и кастомный конфиг Nginx
COPY index.html /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/

# Открываем порт Nginx
EXPOSE 80

# Nginx запускается по умолчанию командой в базовом образе
CMD ["nginx", "-g", "daemon off;"]