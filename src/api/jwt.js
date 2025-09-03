import request from '@/utils/request'

// JWT弱密码漏洞相关接口
export function jwtWeakLogin(data) {
  return request({
    url: 'jwt/weak/login',
    method: 'post',
    data
  })
}

export function jwtWeakGetInfo() {
  return request({
    url: 'jwt/weak/getInfo',
    method: 'get'
  })
}

// JWT强密码安全相关接口
export function jwtStrongLogin(data) {
  return request({
    url: 'jwt/strong/login',
    method: 'post',
    data
  })
}

export function jwtStrongGetInfo() {
  return request({
    url: 'jwt/strong/getInfo',
    method: 'get'
  })
}

// JWT存储敏感信息漏洞相关接口
export function jwtSensitiveVulnLogin(data) {
  return request({
    url: 'jwt/sensitive/vulnLogin',
    method: 'post',
    data
  })
}

export function jwtSensitiveSecLogin(data) {
  return request({
    url: 'jwt/sensitive/secLogin',
    method: 'post',
    data
  })
}

// JWT接受任意签名漏洞相关接口
export function jwtArbitraryLogin(data) {
  return request({
    url: 'jwt/arbitrary/login',
    method: 'post',
    data
  })
}

export function jwtArbitraryGetInfo() {
  return request({
    url: 'jwt/arbitrary/getInfo',
    method: 'get'
  })
}
