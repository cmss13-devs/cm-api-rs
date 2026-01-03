FROM node:20-alpine AS frontend-builder
WORKDIR /app

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ .
ARG VITE_API_PATH=/api
ENV VITE_API_PATH=${VITE_API_PATH}
RUN npm run build

FROM rust:1.89 AS backend-builder
WORKDIR /usr/src/app

COPY backend/Cargo.toml Cargo.toml
COPY backend/Cargo.lock Cargo.lock

RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

COPY backend/src/ src/
RUN touch src/main.rs && cargo install --path .

# Stage 3: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=backend-builder /usr/local/cargo/bin/cm-api-rs /usr/local/bin/cm-api-rs
COPY --from=frontend-builder /app/dist /var/www/static

CMD ["cm-api-rs"]
