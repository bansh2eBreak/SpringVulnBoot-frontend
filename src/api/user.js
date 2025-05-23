import request from '@/utils/request'

export function login(data) {
  return request({
    url: 'login',
    method: 'post',
    data
  })
}

export function getInfo() {
  return request({
    url: 'getAdminInfo',
    method: 'get'
  })
}

export function logout() {
  return request({
    url: 'getAdminInfo',
    method: 'get'
  })
}
