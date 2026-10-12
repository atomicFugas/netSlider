FROM python:3.11-slim
WORKDIR /app
COPY madrigal /app/madrigal
ENV PYTHONPATH=/app
CMD ["python", "-m", "madrigal.demo.client.scripted", "--host", "device", "--port", "9100", "--out", "/corpus/action_log.json"]
