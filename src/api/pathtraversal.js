import request from '@/utils/request'

export function loadImageVuln1(params) {
  return request({
    url: '/pathtraversal/vuln1',
    method: 'get',
    params: params,
    responseType: 'blob'
  })
}

export function loadTextVuln1(params) {
  return request({
    url: '/pathtraversal/vuln1',
    method: 'get',
    params: params,
  })
}

export function loadImageSec1(params) {
  return request({
    url: '/pathtraversal/sec1',
    method: 'get',
    params: params,
    responseType: 'blob'
  })
}

export function loadTextSec1(params) {
  return request({
    url: '/pathtraversal/sec1',
    method: 'get',
    params: params
  })
}

export function loadImageSec2(params) {
  return request({
    url: '/pathtraversal/sec2',
    method: 'get',
    params: params,
    responseType: 'blob'
  })
}

export function loadTextSec2(params) {
  return request({
    url: '/pathtraversal/sec2',
    method: 'get',
    params: params
  })
}