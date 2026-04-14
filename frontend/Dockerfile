# Change from 18-alpine to 20-alpine to satisfy Vite 7 requirements
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./

# Use install instead of ci to handle the dependency mismatch automatically
RUN npm install

COPY . .

RUN npm run build

FROM nginx:stable-alpine
COPY --from=builder /app/dist /usr/share/nginx/html
# Ensure your nginx.conf exists in the frontend folder
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]