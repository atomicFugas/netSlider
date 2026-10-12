FROM python:3.11-slim
WORKDIR /app
COPY madrigal /app/madrigal
ENV PYTHONPATH=/app
EXPOSE 9100
CMD ["python", "-m", "madrigal.demo.device.server", "--host", "0.0.0.0", "--port", "9100"]
