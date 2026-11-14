import request from '@/utils/request'

export function fileuploadVuln1(data) {
  return request({
    url: '/fileUpload/vuln1',
    method: 'post',
    data: data,
  })
}

export function fileuploadSec1(data) {
  return request({
    url: '/fileUpload/sec1',
    method: 'post',
    data: data,
  })
}

export function fileuploadSec2(data) {
  return request({
    url: '/fileUpload/sec2',
    method: 'post',
    data: data
  })
}

export function fileuploadVuln2(data) {
  return request({
    url: '/fileUpload/vuln2',
    method: 'post',
    data: data
  })
}

export function fileuploadVuln3(data) {
  return request({
    url: '/fileUpload/vuln3',
    method: 'post',
    data: data
  })
}

export function getPathTraversalTarget() {
  return request({
    url: '/fileUpload/vuln3/target',
    method: 'get'
  })
}

export function resetPathTraversalTarget() {
  return request({
    url: '/fileUpload/vuln3/reset',
    method: 'post'
  })
}