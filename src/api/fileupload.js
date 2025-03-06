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

export function fileuploadVuln2(data) {
  return request({
    url: '/fileUpload/vuln2',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'image/png'
    }
  })
}

export function fileuploadSec2(data) {
  return request({
    url: '/fileUpload/sec2',
    method: 'post',
    data: data,
  })
}