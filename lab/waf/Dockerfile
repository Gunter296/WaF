FROM caddy:2.11.4-builder AS builder
WORKDIR /src
COPY policy-module ./policy-module
RUN xcaddy build v2.11.4 \
    --with github.com/corazawaf/coraza-caddy/v2@v2.6.1 \
    --with github.com/waf-lab/policy=./policy-module

FROM caddy:2.11.4-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
USER root
RUN mkdir -p /var/log/lab /etc/waf-lab /etc/coraza-lab && chown -R caddy:caddy /var/log/lab /etc/waf-lab
USER caddy
EXPOSE 8080
