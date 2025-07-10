import request from '@/utils/request'

export function bindMfa(data) {
  return request({
    url: '/accessControl/HorizontalPri/bindMfa',
    method: 'post',
    data: data
  })
}

export function resetMfa(data) {
  return request({
    url: '/accessControl/HorizontalPri/resetMfa',
    method: 'post',
    data: data
  })
}

// MFA验证绕过漏洞相关API
export function changePasswordVuln(data) {
  return request({
    url: '/authentication/mfaBased/changePasswordVuln',
    method: 'post',
    data: data
  })
}

export function changePasswordSec(data) {
  return request({
    url: '/authentication/mfaBased/changePasswordSec',
    method: 'post',
    data: data
  })
}

export function getUsers() {
  return request({
    url: '/authentication/mfaBased/users',
    method: 'get'
  })
}

