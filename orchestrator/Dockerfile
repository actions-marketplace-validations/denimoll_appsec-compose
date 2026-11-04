FROM python:3.14-alpine

WORKDIR /app

COPY requirements.txt .
# --only-binary: both deps ship musl wheels (PyYAML) or are pure Python
# (Jinja2), so no toolchain is needed; fail loudly if that ever changes.
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt

COPY . .

# Runtime UID/GID are overridden by compose with the host user's, so the
# collector can write into the bind-mounted reports/ and baseline file.
USER 65532:65532

# A one-shot job that exits when the reports are written: nothing to probe.
HEALTHCHECK NONE

# Reports land in the shared volume; config is mounted read-only at runtime.
ENTRYPOINT ["python", "-u", "main.py"]
