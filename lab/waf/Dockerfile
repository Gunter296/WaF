# syntax=docker/dockerfile:1
# ---
# ARG chỉ cần sửa ở 1 chỗ khi nâng version
# ---
ARG CADDY_VERSION=2.11.4
#ARG CRS_VERSION=4.29.0
# ---
# Stage 1: Build
# Dùng image builder chính thức (đã có sẵn xcaddy + Go)
# [Doc](https://caddyserver.com/docs/build#docker)
FROM caddy:${CADDY_VERSION}-builder AS builder

# Build Caddy với module Coraza WAF nhúng sẵn
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    xcaddy build \
    --with github.com/corazawaf/coraza-caddy/v2
    
# Chốt chặn: binary phải có module coraza, nếu không build fail NGAY
RUN caddy list-modules | grep -i waf

# ---
# Stage 2: Runtime
# Image Caddy chính thức (Alpine, đã có user caddy, entrypoint chuẩn)
FROM caddy:${CADDY_VERSION}-alpine

ARG CRS_VERSION

# Copy binary đã nhúng Coraza từ stage build (ghi đè binary gốc)
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Thư mục log cho Coraza (image chính thức chạy user caddy, cần quyền ghi)
USER root

# Thư mục log cho Coraza
RUN mkdir -p /etc/coraza /var/log/caddy && \
    # Kiểm tra nếu group caddy chưa có thì tạo mới
    getent group caddy || addgroup -S caddy && \
    # Kiểm tra nếu user caddy chưa có thì tạo mới
    getent passwd caddy || adduser -S -G caddy caddy && \
    # Phân quyền cho thư mục
    chown -R caddy:caddy /var/log/caddy /etc/coraza

# Tải OWASP Core Rule Set
#RUN wget -q https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz && \
#    tar -xzf v${CRS_VERSION}.tar.gz && \
#    mv coreruleset-${CRS_VERSION} /etc/coraza/crs && \
#    rm v${CRS_VERSION}.tar.gz && \
#    chown -R caddy:caddy /etc/coraza

# Chuyển lại về user caddy chạy container bằng quyền user thường
USER caddy

# Config (Caddyfile, coraza.conf, crs-setup.conf đặt cùng thư mục với Dockerfile)
#COPY Caddyfile /etc/caddy/Caddyfile
#COPY coraza.conf /etc/coraza/coraza.conf
#COPY crs-setup.conf /etc/coraza/crs/crs-setup.conf


EXPOSE 8080

# caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
