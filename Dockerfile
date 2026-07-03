FROM node:24-slim AS frontend
WORKDIR /frontend/
COPY ./frontend/package.json ./frontend/package-lock.json /frontend/
RUN npm ci
COPY ./frontend /frontend
RUN npm run build

FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.11.16 /uv /bin/uv
WORKDIR /app/

RUN apt update && apt install --no-install-recommends -y git && rm -rf /var/lib/apt/lists/*

# Setup the git config for private repos
RUN --mount=type=secret,id=github_pat,uid=50000 git config --global url."https://git:$(cat /run/secrets/github_pat)@github.com/".insteadOf "git@github.com:"

# python conf
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

# Copy src
COPY ./src /app/src
COPY ./pyproject.toml ./uv.lock ./README.md /app/
COPY --from=frontend /frontend/dist /app/frontend/dist

# Install deps from the lockfile (reproducible — honours uv.lock pins)
RUN uv sync --locked && uv pip install uvicorn
ENV PATH="/app/.venv/bin:$PATH"

# Entrypoint
CMD ["uvicorn", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--interface", "wsgi", "cactus_ui.server:app"]
