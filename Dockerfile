FROM python:3.12-slim

# Run as an unprivileged user — the gate binds a high port and needs no root.
RUN useradd --system --no-create-home gate
USER gate

WORKDIR /app
COPY app.py .

EXPOSE 8080
CMD ["python", "app.py"]
