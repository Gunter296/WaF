FROM node:22.16.0-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-package-lock
COPY server.mjs tuning.mjs automation.mjs ip-policy.mjs logs.mjs ./
COPY public ./public
USER node
EXPOSE 8090
CMD ["node", "server.mjs"]
