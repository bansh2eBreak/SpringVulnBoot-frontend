import request from '@/utils/request'

/**
 * CSRF演示 - 修改密码接口（存在CSRF漏洞）
 * 只验证新密码，不验证旧密码
 */
export function changePasswordVuln(data) {
  return request({
    url: '/csrf/changePasswordVuln',
    method: 'post',
    data
  })
}

/**
 * CSRF演示 - 修改密码接口（CSRF防护）
 * 验证旧密码，防止CSRF攻击
 */
export function changePasswordSecure(data) {
  return request({
    url: '/csrf/changePasswordSecure',
    method: 'post',
    data
  })
}

/**
 * 管理员实际使用 - 修改密码接口
 * 用于管理员日常修改密码
 */
export function changePassword(data) {
  return request({
    url: '/changePassword',
    method: 'post',
    data
  })
}

/**
 * 生成CSRF Token
 * 用于CSRF Token防护演示
 */
export function generateCsrfToken() {
  return request({
    url: '/csrf/generateToken',
    method: 'get'
  })
}

/**
 * CSRF演示 - 修改密码接口（CSRF Token防护）
 * 使用CSRF Token机制防止CSRF攻击
 */
export function changePasswordWithToken(data) {
  return request({
    url: '/csrf/changePasswordWithToken',
    method: 'post',
    data
  })
}
