FROM python:3.14-slim@sha256:930e1abba7c4e8f96ed93e8012c35d174d7732752731bbd5e8e757d7ec6f3966
ARG HERMES_REVISION
LABEL org.nexus.hermes.revision=$HERMES_REVISION org.nexus.hermes.protocol="1"
ENV UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never
RUN pip install --no-cache-dir uv==0.13.7
COPY upstream /opt/hermes
WORKDIR /opt/hermes
RUN uv sync --frozen --no-dev
COPY worker.py /opt/nexus/worker.py
ENV HERMES_HOME=/tmp/hermes HOME=/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT ["/opt/venv/bin/python", "/opt/nexus/worker.py"]
