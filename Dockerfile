# Smart Contract Auditor Dockerfile
# Multi-stage build with Slither and Foundry

FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install uv

# Copy dependency files
COPY pyproject.toml requirements.txt ./

# Create virtual environment and install dependencies
RUN uv venv /app/.venv && \
    . /app/.venv/bin/activate && \
    uv pip install -r requirements.txt

# Copy source code
COPY src/ ./src/

# Install the package
RUN . /app/.venv/bin/activate && \
    uv pip install .

# Production stage with Slither and Foundry
FROM python:3.12-slim as production

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Slither
RUN pip install slither-analyzer solc-select && \
    solc-select install 0.8.20 && \
    solc-select use 0.8.20

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup

# Add Foundry to PATH
ENV PATH="/root/.foundry/bin:$PATH"

# Create non-root user
RUN groupadd -r auditor && useradd -r -g auditor auditor

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy source code
COPY --from=builder /app/src ./src

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Create directories
RUN mkdir -p /app/reports /app/contracts && \
    chown -R auditor:auditor /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import contract_auditor; print('healthy')" || exit 1

# Default command
ENTRYPOINT ["python", "-m", "contract_auditor.cli"]
CMD ["--help"]
