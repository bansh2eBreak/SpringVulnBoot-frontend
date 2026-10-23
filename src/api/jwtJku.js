import request, { getBaseUrl } from '@/utils/request'

export function attackerJku() {
  return getBaseUrl() + '/jwt/jku/attacker/jwks.json'
}

export function jkuLogin(username, password) {
  return request({
    url: '/jwt/jku/login',
    method: 'post',
    data: { username, password }
  })
}

export function publishAttackerJwk(jwk) {
  return request({
    url: '/jwt/jku/attacker/jwks',
    method: 'post',
    data: { jwk }
  })
}

export function querySalary(token) {
  return request({
    url: '/jwt/jku/salary',
    method: 'post',
    data: { token }
  })
}

export function querySalaryVuln(token) {
  return request({
    url: '/jwt/jku/vuln/salary',
    method: 'post',
    data: { token }
  })
}

export function querySalarySec(token) {
  return request({
    url: '/jwt/jku/sec/salary',
    method: 'post',
    data: { token }
  })
}
