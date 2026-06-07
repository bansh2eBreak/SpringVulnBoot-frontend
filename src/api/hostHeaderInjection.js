import request from '@/utils/request'

/**
 * 漏洞版"忘记密码"接口
 * 后端用 request.getHeader("Host") 拼接 reset link，攻击者可投毒
 * 浏览器无法自定义 Host 头，所以正常调用时 Host = 当前后端 hostname:8080
 * 投毒攻击只能通过 curl 命令演示
 */
export function forgotPasswordVuln(username) {
  return request({
    url: '/hostHeaderInjection/forgot-password/vuln',
    method: 'post',
    data: { username }
  })
}

/**
 * 安全版"忘记密码"接口
 * 后端从 application.yml 的 app.base-url 读 baseUrl，Host 头无效
 */
export function forgotPasswordSec(username) {
  return request({
    url: '/hostHeaderInjection/forgot-password/sec',
    method: 'post',
    data: { username }
  })
}

/**
 * 用 token 重置密码（模拟攻击者拿到 token 后的账号接管动作）
 */
export function resetPassword(token, newPassword) {
  return request({
    url: '/hostHeaderInjection/reset',
    method: 'post',
    data: { token, newPassword }
  })
}
