# Serve the static app with plain nginx (no CSP header: MediaPipe needs WebAssembly).
FROM nginx:1.27-alpine
ENV PORT=8080
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY index.html /usr/share/nginx/html/index.html
