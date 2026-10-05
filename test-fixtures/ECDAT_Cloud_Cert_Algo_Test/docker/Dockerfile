FROM python:3.13-slim
RUN pip install cryptography
COPY ../python/crypto_algorithms.py /app/crypto_algorithms.py
ENV TLS_CIPHER=ECDHE-RSA-AES256-GCM-SHA384
ENV KMS_ALGORITHM=RSA_2048
CMD ["python", "/app/crypto_algorithms.py"]
