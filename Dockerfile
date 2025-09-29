
# Use official Python image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy application files
COPY waf.py waf.py
COPY waf_config.yaml waf_config.yaml

# Install dependencies
RUN pip install flask pyyaml

# Expose port
EXPOSE 8080

# Run the WAF application
CMD ["python", "waf.py"]
