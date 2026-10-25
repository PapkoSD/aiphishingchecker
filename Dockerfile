FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY phishchecker/ phishchecker/
COPY samples/ samples/

# Listen on all interfaces inside the container; Docker's -p flag decides
# what is reachable from outside. No browser to open in a container.
ENV HOST=0.0.0.0 PORT=8000 NO_BROWSER=1
EXPOSE 8000

RUN useradd --create-home checker
USER checker

HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

CMD ["python", "-m", "phishchecker"]
