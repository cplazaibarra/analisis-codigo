FROM python:3.10-alpine

# Instalar Docker CLI y Git
RUN apk add --no-cache docker-cli git

# Crear directorio de la aplicación
WORKDIR /app

# Instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código del receptor
COPY app.py .

# Comando de inicio
CMD ["python", "app.py"]
