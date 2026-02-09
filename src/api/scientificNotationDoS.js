import request from '@/utils/request'

/**
 * 测试科学记数法DoS漏洞代码
 * @param {string} num - 科学记数法字符串（如 0.1e-121312222）
 */
export function testScientificNotationDoSVuln(num) {
  return request({
    url: '/scientificNotationDoS/vuln',
    method: 'post',
    params: { num }
  })
}

/**
 * 测试科学记数法DoS安全代码
 * @param {string} num - 科学记数法字符串
 */
export function testScientificNotationDoSSafe(num) {
  return request({
    url: '/scientificNotationDoS/sec',
    method: 'post',
    params: { num }
  })
}
