import request from '@/utils/request'

export function vulnPing(params) {
  return request({
    url: '/rce/vulnPing',
    method: 'get',
    params: params
  })
}

export function secPing(params) {
  return request({
    url: '/rce/secPing',
    method: 'get',
    params: params
  })
}

export function vulnPing2(params) {
  return request({
    url: '/rce/vulnPing2',
    method: 'get',
    params: params
  })
}

export function secPing2(params) {
  return request({
    url: '/rce/secPing2',
    method: 'get',
    params: params
  })
}

