import request from '@/utils/request'

export function fastjsonVuln1(data) {
  return request({
    url: '/components/fastjson/vuln1',
    method: 'post',
    data: data
  })
}

export function fastjsonSec1(data) {
  return request({
    url: '/components/fastjson/sec1',
    method: 'post',
    data: data
  })
}