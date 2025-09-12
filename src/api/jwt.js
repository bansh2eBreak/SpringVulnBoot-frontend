import request from '@/utils/request'

// JWT弱密码漏洞相关接口
export function jwtWeakLogin(data) {
  return request({
    url: 'jwt/weak/weakLogin',
    method: 'post',
    data
  })
}

export function jwtWeakGetInfo() {
  return request({
    url: 'jwt/weak/weakGetInfo',
    method: 'get'
  })
}

// JWT强密码安全相关接口
export function jwtStrongLogin(data) {
  return request({
    url: 'jwt/weak/strongLogin',
    method: 'post',
    data
  })
}

export function jwtStrongGetInfo() {
  return request({
    url: 'jwt/weak/strongGetInfo',
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

// JWT None算法漏洞相关接口
export function jwtSignatureVulnLogin(data) {
  return request({
    url: 'jwt/signature/vulnLogin',
    method: 'post',
    data
  })
}

export function jwtSignatureVulnGetInfo() {
  return request({
    url: 'jwt/signature/vulnGetInfo',
    method: 'get'
  })
}

export function jwtSignatureSecureLogin(data) {
  return request({
    url: 'jwt/signature/secureLogin',
    method: 'post',
    data
  })
}

export function jwtSignatureSecureGetInfo() {
  return request({
    url: 'jwt/signature/secureGetInfo',
    method: 'get'
  })
}

