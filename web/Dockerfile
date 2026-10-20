# Build context is the repo ROOT (consistent with the other services).
# The bundle is platform-independent, so build it natively for every target.
FROM --platform=$BUILDPLATFORM node:22-alpine AS build
WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM nginx:alpine
COPY web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
