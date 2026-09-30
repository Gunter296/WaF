FROM node:22.16.0-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-package-lock
COPY server.mjs ./
COPY tuning.mjs ./
COPY ip-policy.mjs ./
COPY automation.mjs ./
COPY index.html ./
USER node
EXPOSE 8090
CMD ["node", "server.mjs"]
