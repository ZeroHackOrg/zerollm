# syntax=docker/dockerfile:1
FROM python:3.13-slim

ARG ZEROLM_EXTRAS="otel s3 ha"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/home/zerollm/.local/bin:$PATH"

WORKDIR /opt/zerollm

RUN groupadd --gid 1001 zerollm && useradd --uid 1001 --gid zerollm --no-create-home zerollm

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --upgrade pip setuptools wheel \
    && pip install --user ".[$ZEROLM_EXTRAS]"

USER zerollm
EXPOSE 8080

VOLUME ["/data"]

ENV ZEROLM_CONFIG=/etc/zerollm/zerollm.yaml

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; \
  sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status==200 else 1)" \
  || exit 1

ENTRYPOINT ["zerollm"]
CMD ["proxy", "--config", "/etc/zerollm/zerollm.yaml"]