import request from '@/utils/request'

export function redirect(params) {
  return request({
    url: '/openUrl/redirect',
    method: 'get',
    params: params
  })
}

export function redirect2(params) {
  return request({
    url: '/openUrl/redirect2',
    method: 'get',
    params: params
  })
}
