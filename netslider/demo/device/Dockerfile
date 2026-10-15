FROM python:3.11-slim
WORKDIR /app
COPY netslider /app/netslider
ENV PYTHONPATH=/app
EXPOSE 9100
CMD ["python", "-m", "netslider.demo.device.server", "--host", "0.0.0.0", "--port", "9100"]
