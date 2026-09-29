FROM node:22.16.0-alpine AS dependencies
WORKDIR /app
COPY package.json ./
ARG NEXT_VERSION=16.2.10
RUN npm pkg set "dependencies.next=${NEXT_VERSION}" && npm install --no-package-lock

FROM node:22.16.0-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
ARG NEXT_VERSION=16.2.10
RUN npm run build
USER node
EXPOSE 3000
CMD ["npm", "run", "start"]
