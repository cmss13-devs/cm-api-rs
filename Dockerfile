# Stage 1: Build frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app

COPY frontend/ .

ARG VITE_API_PATH=/api
ENV VITE_API_PATH=${VITE_API_PATH}
RUN npm ci && npm run build

# Stage 2: Build backend
FROM rust:1.85 AS backend-builder
WORKDIR /usr/src/app
COPY backend/src/ src/
COPY backend/Cargo.toml Cargo.toml
COPY backend/Cargo.lock Cargo.lock
RUN cargo install --path .

# Stage 3: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=backend-builder /usr/local/cargo/bin/cm-api-rs /usr/local/bin/cm-api-rs
COPY --from=frontend-builder /app/dist /var/www/static

CMD ["cm-api-rs"]
