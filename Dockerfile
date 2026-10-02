FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016
WORKDIR /app
RUN useradd --system --uid 10001 --create-home --home-dir /home/bsa bsa \
    && mkdir -p /data \
    && chown -R bsa:bsa /app /data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=bsa:bsa app ./app
USER bsa
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
