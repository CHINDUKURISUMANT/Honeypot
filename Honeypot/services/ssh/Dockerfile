# services/ssh/Dockerfile

FROM python:3.10-slim

WORKDIR /app

COPY ssh_honeypot.py .

RUN pip install "paramiko>=3.4,<4.0" requests

EXPOSE 2222

CMD ["python", "ssh_honeypot.py"]
