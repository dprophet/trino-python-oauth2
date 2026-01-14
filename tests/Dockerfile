FROM python:3.11

# Set working directory
WORKDIR /app

# Copy requirements files
COPY ../requirements-dev.txt /app/requirements-dev.txt
COPY ../pyproject.toml /app/pyproject.toml

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements-dev.txt

# Copy test files
COPY . /app

# Set PYTHONPATH so imports work correctly
ENV PYTHONPATH=/app/src:/app

# Set working directory to run tests
WORKDIR /app

# Default command to run pytest
CMD ["pytest", "-v", "tests/"]

