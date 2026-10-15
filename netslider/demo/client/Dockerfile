FROM python:3.11-slim
WORKDIR /app
COPY netslider /app/netslider
ENV PYTHONPATH=/app
CMD ["python", "-m", "netslider.demo.client.scripted", "--host", "device", "--port", "9100", "--out", "/corpus/action_log.json"]
