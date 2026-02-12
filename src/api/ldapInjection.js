import request from '@/utils/request'

// LDAP 注入漏洞代码测试
export function ldapVulnLogin(data) {
  return request({
    url: '/api/ldap/vuln/login',
    method: 'post',
    data: {
      username: data.username,
      password: data.password
    }
  })
}

// LDAP 注入安全代码测试
export function ldapSafeLogin(data) {
  return request({
    url: '/api/ldap/safe/login',
    method: 'post',
    data: {
      username: data.username,
      password: data.password
    }
  })
}
