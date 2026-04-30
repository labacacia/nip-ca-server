FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json .
COPY src ./src
COPY db ./db
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app

RUN addgroup -g 1001 nipca \
 && adduser -u 1001 -G nipca -D nipca \
 && mkdir -p /data && chown nipca:nipca /data

COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY db ./db

USER nipca
EXPOSE 17440

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:17440/health || exit 1

CMD ["node", "dist/index.js"]
