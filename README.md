# SpringVulnBoot Frontend

## 项目介绍

基于 Vue + SpringBoot 构建的 Java 安全靶场，一个专为安全爱好者、开发人员和渗透测试人员打造的实战演练平台。

1. 前端是基于流行的vue-admin-template基础模板进行改改改，[前端工程](https://github.com/bansh2eBreak/SpringVulnBoot-frontend)
2. 后端是基于springBoot开发的，[后端工程](https://github.com/bansh2eBreak/SpringVulnBoot-backend)

如需快速部署，请移步[后端工程](https://github.com/bansh2eBreak/SpringVulnBoot-backend)。

## 靶场已编写的漏洞

- SQLi注入
  - 基于Jdbc的SQLi注入
  - 基于Mybatis的SQLi注入
  - 报错注入
- XSS跨站脚本
  - 反射型XSS
  - 存储型XSS
- 任意命令执行
  - Runtime方式
  - ProcessBuilder方式
- 任意URL跳转
- 路径穿越漏洞
- 文件上传漏洞
- 越权漏洞
  - 水平越权漏洞
  - 垂直越权漏洞
  - 未授权访问漏洞
- 身份认证漏洞
  - 密码登录暴力破解
    - 普通的账号密码登录暴力破解
    - 绕过单IP限制暴力破解
    - HTTP Basic认证登录暴力破解
    - 图形验证码登录暴力破解
  - 短信认证漏洞
    - 短信轰炸
    - 短信验证码回显
    - 暴力破解短信验证码
- 组件漏洞
  - Fastjson漏洞
  - Log4j2漏洞

## 未完待续

- SSRF漏洞
- CSRF漏洞
- 逻辑漏洞
- 配置漏洞

## vue-admin-template

> 这是一个极简的 vue admin 管理后台。它只包含了 Element UI & axios & iconfont & permission control & lint，这些搭建后台必要的东西。

[线上地址](http://panjiachen.github.io/vue-admin-template)

[国内访问](https://panjiachen.gitee.io/vue-admin-template)
