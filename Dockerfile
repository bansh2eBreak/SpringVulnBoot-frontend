# 构建阶段
FROM node:16 as build-stage
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build:prod

# 生产阶段
FROM nginx:stable-alpine as production-stage
COPY --from=build-stage /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
# CORS 漏洞演示 - 攻击者模拟站点（端口 81，独立 Origin）
COPY attacker.html /usr/share/nginx/attacker/attacker.html
EXPOSE 80 81
CMD ["nginx", "-g", "daemon off;"]