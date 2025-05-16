FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    tcpdump \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["python", "-m", "app.main"]