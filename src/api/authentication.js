import request from '@/utils/request'

export function vuln1(data) {
  return request({
    url: '/authentication/passwordBased/vuln1',
    method: 'post',
    data: data
  })
}

export function vuln2(data, headers = {}) {
  return request({
    url: '/authentication/passwordBased/vuln2',
    method: 'post',
    headers: headers,
    data: data
  })
}

export function sec(data) {
  return request({
    url: '/authentication/passwordBased/sec',
    method: 'post',
    data: data
  })
}