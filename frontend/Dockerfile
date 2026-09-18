# ---------------------------------------------------------------------------
# DocuTrust frontend image
#
# Builds the static bundle, then serves it from nginx. The runtime image
# contains no Node.js and no node_modules - only the compiled assets.
# ---------------------------------------------------------------------------

# ------------------------------- build -------------------------------------
FROM node:22-alpine AS build

WORKDIR /build

# `npm ci` installs exactly what the lockfile pins, so a build cannot silently
# pick up a different dependency version than the one that was tested.
COPY package.json package-lock.json* ./
RUN npm ci

COPY . .
RUN npm run build

# ------------------------------ runtime ------------------------------------
FROM nginx:1.27-alpine AS runtime

COPY --from=build /build/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget --spider -q http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
