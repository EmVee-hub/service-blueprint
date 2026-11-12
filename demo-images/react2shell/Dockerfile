# Known vulnerable React package metadata; no runtime server is included.
FROM node:22-alpine AS deps
RUN npm install --prefix /opt/demo --ignore-scripts --omit=dev --no-audit --no-fund --legacy-peer-deps react-server-dom-webpack@19.0.0 react@19.0.0 react-dom@19.0.0
FROM alpine:3.22
COPY --from=deps /opt/demo/node_modules/ /opt/demo/node_modules/
CMD ["sh", "-c", "echo 'SCAN ONLY - no React server started'"]
