import request from '@/utils/request'

export function fastjsonVuln1(data) {
  return request({
    url: '/components/fastjsonVuln1',
    method: 'post',
    data: data
  })
}

export function fastjsonSec1(data) {
  return request({
    url: '/components/fastjsonSec1',
    method: 'post',
    data: data
  })
}