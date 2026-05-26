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
# ClickJacking 漏洞演示 - 攻击者钓鱼页（端口 81，独立 Origin）
COPY clickjacking-attacker.html /usr/share/nginx/attacker/clickjacking-attacker.html
# ClickJacking 漏洞演示 - 受害者页面（端口 80，与靶场前端同 Origin，可访问 localStorage 中的 JWT）
COPY clickjacking-victim-vuln.html /usr/share/nginx/html/clickjacking-victim-vuln.html
COPY clickjacking-victim-sec.html /usr/share/nginx/html/clickjacking-victim-sec.html
EXPOSE 80 81
CMD ["nginx", "-g", "daemon off;"]