import request from '@/utils/request'

export function previewImageVuln(url) {
  return request({
    url: '/ssrf/vuln1',
    method: 'get',
    params: { url }
  })
}

export function previewImageSec(url) {
  return request({
    url: '/ssrf/sec1',
    method: 'get',
    params: { url }
  })
} 