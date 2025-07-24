import request from '@/utils/request'

// SnakeYAML反序列化漏洞测试
export function snakeyamlVuln1(data) {
  return request({
    url: '/components/snakeyaml/vuln1',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'text/plain'
    }
  })
}

// SnakeYAML安全代码测试
export function snakeyamlSec1(data) {
  return request({
    url: '/components/snakeyaml/sec1',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'text/plain'
    }
  })
} 

// SnakeYAML正常测试
export function basicTest(data) {
  return request({
    url: '/components/snakeyaml/basictest',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'text/plain'
    }
  })
}