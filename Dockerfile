FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --chown=node:node src ./src
COPY --chown=node:node api ./api
RUN chown node:node /app
USER node
EXPOSE 3005
CMD ["node", "src/index.js"]
