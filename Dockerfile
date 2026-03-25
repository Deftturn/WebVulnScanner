FROM mcr.microsoft.com/playwright/python:v1.42.0

WORKDIR /webvulnscanner

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY /webvulnscanner .

RUN playwright install --with deps

CMD ["python", "main.py"]