import request from '@/utils/request'

/**
 * 漏洞1：Origin 完全信任
 * 后端 CorsConfig 对此路径配置了 addAllowedOriginPattern("*") + allowCredentials(true)
 * 任意来源的恶意页面均可携带受害者凭证读取响应
 */
export function corsVuln1() {
  return request({
    url: '/cors/vuln1/sensitiveData',
    method: 'get'
  })
}

/**
 * 漏洞2：Origin 校验可绕过
 * 后端使用 origin.contains("secnotes") 做校验，看似安全，实则可被绕过
 * 攻击者注册 http://evilsecnotes.com 即可通过校验
 */
export function corsVuln2() {
  return request({
    url: '/cors/vuln2/sensitiveData',
    method: 'get'
  })
}

/**
 * 安全版：严格白名单
 * 后端仅允许 http://trusted.secnotes.icu，当前前端不在白名单内
 * 浏览器将直接报 CORS 错误，无法读取响应（演示防御效果）
 */
export function corsSecure() {
  return request({
    url: '/cors/secure/sensitiveData',
    method: 'get'
  })
}
