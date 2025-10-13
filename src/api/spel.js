import request from '@/utils/request'

/**
 * SpEL表达式注入 - 漏洞接口
 * 使用StandardEvaluationContext，存在表达式注入漏洞
 */
export function spelVulnerable(data) {
  return request({
    url: '/spel/vuln',
    method: 'post',
    data
  })
}

/**
 * SpEL表达式注入 - 黑名单过滤接口（可被绕过）
 * 使用黑名单过滤危险关键字，但过滤不完善
 */
export function spelFilter(data) {
  return request({
    url: '/spel/filter',
    method: 'post',
    data
  })
}

/**
 * SpEL表达式注入 - 安全接口
 * 使用SimpleEvaluationContext，限制SpEL能力
 */
export function spelSecure(data) {
  return request({
    url: '/spel/sec',
    method: 'post',
    data
  })
}
