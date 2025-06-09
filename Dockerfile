FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create reports directory
RUN mkdir -p reports

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the application
ENTRYPOINT ["python", "recon_it.py"] 