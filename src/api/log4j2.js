import request from '@/utils/request'

export function log4j2Vuln1(params) {
  return request({
    url: '/components/log4j2/vuln1',
    method: 'get',
    params: params
  })
}

export function log4j2Sec1(params) {
  return request({
    url: '/components/log4j2/sec1',
    method: 'get',
    params: params
  })
}