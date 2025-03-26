FROM python:3.13-alpine as builder

RUN apk add --no-cache gcc musl-dev libffi-dev cmake make build-base unzip

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

ADD https://github.com/DFIR-ORC/orc-decrypt/archive/refs/heads/master.zip /tmp/orc-decrypt.zip
RUN unzip /tmp/orc-decrypt.zip -d /tmp \
    && pip install --no-cache-dir /tmp/orc-decrypt-master \
    && rm -rf /tmp/orc-decrypt.zip /tmp/orc-decrypt-master

FROM python:3.13-alpine

RUN apk add --no-cache p7zip bash openssl

COPY --from=builder /app /app
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin/orc-decrypt /usr/local/bin/orc-decrypt
COPY --from=builder /usr/local/bin/unstream /usr/local/bin/unstream

RUN mkdir /data
WORKDIR /data

ENTRYPOINT ["python", "/app/orc2tree.py"]