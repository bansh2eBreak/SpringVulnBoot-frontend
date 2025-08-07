import request from '@/utils/request'

// 获取Shiro-550漏洞信息

// 生成URLDNS链payload
export function generateURLDNSPayload(dnsUrl) {
  return request({
    url: '/components/shiro/generate/urldns',
    method: 'post',
    params: { dnsUrl }
  })
}

// Shiro登录
export function shiroLogin(data) {
  return request({
    url: '/components/shiro/login',
    method: 'post',
    params: data
  })
}

// Shiro登出
export function shiroLogout() {
  return request({
    url: '/components/shiro/logout',
    method: 'get'
  })
}

// 测试权限
export function testPermission(permission) {
  return request({
    url: `/components/shiro/test/permission/${permission}`,
    method: 'get'
  })
}

// 测试角色
export function testRole(role) {
  return request({
    url: `/components/shiro/test/role/${role}`,
    method: 'get'
  })
}

 