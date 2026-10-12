import request from '@/utils/request'

/**
 * 漏洞版"忘记密码"：后端用 new Random(System.currentTimeMillis()) 生成可预测 token
 * 返回秒级服务器时间（不返回 token）
 */
export function forgotPasswordVuln(username) {
  return request({
    url: '/cryptoSecurity/predictableSeed/forgot-password/vuln',
    method: 'post',
    data: { username }
  })
}

/**
 * 安全版"忘记密码"：后端用 SecureRandom 生成不可预测 token
 */
export function forgotPasswordSec(username) {
  return request({
    url: '/cryptoSecurity/predictableSeed/forgot-password/sec',
    method: 'post',
    data: { username }
  })
}

/**
 * 用 token 重置密码（爆破目标）
 */
export function resetPassword(token, newPassword) {
  return request({
    url: '/cryptoSecurity/predictableSeed/reset',
    method: 'post',
    data: { token, newPassword }
  })
}
