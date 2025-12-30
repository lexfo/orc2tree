# --- Étape Builder ---
    FROM python:3.13-slim as builder

    RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc python3-dev libffi-dev cmake make g++ unzip curl \
        && rm -rf /var/lib/apt/lists/*
    
    WORKDIR /app
    RUN python -m venv /opt/venv
    ENV PATH="/opt/venv/bin:$PATH"
    
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt
    
    ADD https://github.com/DFIR-ORC/orc-decrypt/archive/refs/heads/master.zip /tmp/orc-decrypt.zip
    RUN unzip /tmp/orc-decrypt.zip -d /tmp \
        && pip install --no-cache-dir /tmp/orc-decrypt-master
    
    # --- Étape Finale ---
    FROM python:3.13-slim
    
    RUN apt-get update && apt-get install -y --no-install-recommends \
        p7zip-full openssl \
        && rm -rf /var/lib/apt/lists/*
    
    # 1. Création d'un utilisateur système (sans mot de passe, sans home inutile)
    RUN groupadd -g 1000 appuser && \
        useradd -u 1000 -g appuser -s /bin/sh appuser
    
    # 2. Préparation des répertoires
    RUN mkdir /app /data && chown appuser:appuser /app /data
    
    # 3. Récupération du venv et du code
    COPY --from=builder /opt/venv /opt/venv
    COPY --chown=appuser:appuser . /app
    
    ENV PATH="/opt/venv/bin:$PATH"
    ENV PYTHONDONTWRITEBYTECODE=1
    ENV PYTHONUNBUFFERED=1
    
    WORKDIR /data
    
    # 4. Passage à l'utilisateur non-privilégié
    USER appuser
    
    ENTRYPOINT ["python", "/app/orc2tree.py"]