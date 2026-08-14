# Runs one evaluated artifact, unmodified, behind the plain-HTTP port that
# Cloudflare Containers reaches. Which artifact is chosen at start time by the
# ARTIFACT environment variable, set by the Worker.
FROM oven/bun:1.3.14-slim

WORKDIR /app

# openssl is only needed to mint the self-signed certificate the artifacts
# require. Nothing else is installed.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*

# The artifacts insist on TLS at ./certs and exit if it is absent. This
# certificate is never seen by a browser: it secures the loopback hop between
# the proxy and the artifact, inside a single container.
RUN mkdir -p certs \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout certs/key.pem -out certs/cert.pem \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
 && chmod 600 certs/key.pem

# The six artifacts, byte-identical to the model output. Their SHA-256 sums
# still match generations/<story>/batch_manifest.json.
COPY artifacts/ ./artifacts/

# Harness, clearly separated from the artifacts it serves.
COPY proxy.ts entrypoint.sh ./
RUN chmod +x entrypoint.sh

ENV APP_PORT=8443 \
    PROXY_PORT=8080 \
    PORT=8443

EXPOSE 8080

ENTRYPOINT ["./entrypoint.sh"]
