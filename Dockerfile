# TRACESETTLE — read-only NEAR Intents settlement investigator.
#
# Runtime has zero third-party dependencies (Python standard library only), so
# the image needs no pip install. It runs as a non-root user and binds the
# interface given by TRACESETTLE_HOST/PORT (defaults: 0.0.0.0:8000 inside the
# container, so the port is reachable from outside it).
FROM python:3.13-slim

# Keep Python quiet and unbuffered so logs stream to the container log.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRACESETTLE_HOST=0.0.0.0 \
    PORT=8000

WORKDIR /app

# Only the package and the metadata a reader needs are copied in.
COPY tracesettle/ ./tracesettle/
COPY README.md ./

# Create an unprivileged user and drop to it. With durable guard state unset the
# tool writes nothing to the filesystem; to enable durable state, mount a volume
# writable by this uid and point TRACESETTLE_GUARD_STATE_DB at it.
RUN useradd --create-home --uid 10001 tracesettle \
    && chown -R tracesettle:tracesettle /app
USER tracesettle

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import os,urllib.request; \
port=os.environ.get('PORT','8000'); \
urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health', timeout=4).read()" || exit 1

CMD ["python", "-m", "tracesettle", "serve"]
