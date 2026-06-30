FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (like libgomp1) required by LightGBM and XGBoost
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache layers
COPY requirements.txt .

# Install python packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY src/ ./src/

# Copy the trained models folder
COPY models/ ./models/

# Define default environment variables
ENV MODEL_PATH=/app/models/ransomware_detector_custom.pkl
ENV MONITOR_DIR=/app/monitored_folder
ENV NOTIFY_URL=http://host.docker.internal:5454/notify

# Create monitored folder directory inside container
RUN mkdir -p /app/monitored_folder

# Default execution mode: monitor the mounted folder
CMD ["python", "-B", "-m", "src.main", \
     "--mode", "monitor", \
     "--monitor-dir", "/app/monitored_folder", \
     "--model-path", "/app/models/ransomware_detector_custom.pkl", \
     "--notify-url", "http://host.docker.internal:5454/notify"]
