FROM caddy:2.11.4-builder AS builder
WORKDIR /src
COPY policy-module ./policy-module
RUN xcaddy build v2.11.4 \
    --output /usr/bin/caddy \
    --with github.com/corazawaf/coraza-caddy/v2@v2.6.1 \
    --with github.com/waf-lab/policy=./policy-module
RUN /usr/bin/caddy list-modules --skip-standard | grep -Fx 'http.handlers.lab_policy' \
    && /usr/bin/caddy list-modules --skip-standard | grep -Fx 'http.handlers.waf'

FROM caddy:2.11.4-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
RUN mkdir -p /var/log/lab /etc/waf-lab /etc/coraza-lab
EXPOSE 8080

