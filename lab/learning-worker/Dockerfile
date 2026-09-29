FROM node:22.16.0-alpine
WORKDIR /app
COPY worker.mjs learning.mjs ./
USER node
CMD ["node", "worker.mjs"]
