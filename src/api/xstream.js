import request from '@/utils/request'

// XStream反序列化漏洞测试
export function xstreamVuln1(data) {
  return request({
    url: '/components/xstream/vuln1',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'text/plain'
    }
  })
}

// XStream安全代码测试 - 白名单验证
export function xstreamSec1(data) {
  return request({
    url: '/components/xstream/sec1',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'text/plain'
    }
  })
}

// XStream安全代码测试 - 安全配置
export function xstreamSec2(data) {
  return request({
    url: '/components/xstream/sec2',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'text/plain'
    }
  })
}

// XStream XML反序列化功能测试
export function xstreamBasicTest(data) {
  return request({
    url: '/components/xstream/deserializePersonFromXml',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'text/plain'
    }
  })
}

// XML序列化Person对象
export function serializePerson(data) {
  return request({
    url: '/components/xstream/serializePersonToXml',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/json'
    }
  })
}

// JSON序列化Person对象
export function serializePersonToJson(data) {
  return request({
    url: '/components/xstream/serializePersonToJson',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/json'
    }
  })
}

// JSON反序列化Person对象
export function deserializePersonFromJson(data) {
  return request({
    url: '/components/xstream/deserializePersonFromJson',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'text/plain'
    }
  })
}
