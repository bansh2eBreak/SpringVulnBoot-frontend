import request from '@/utils/request'


// XMLDecoder反序列化漏洞测试
export function xmlDecoderVuln1(data) {
  return request({
    url: '/components/xmldecoder/vuln1',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'text/plain'
    }
  })
}

// XMLDecoder安全代码测试
export function xmlDecoderSec1(data) {
  return request({
    url: '/components/xmldecoder/sec1',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'text/plain'
    }
  })
}

// XMLEncoder序列化测试
export function xmlEncoderTest(data) {
  return request({
    url: '/components/xmldecoder/basictest',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'text/plain'
    }
  })
}

// 序列化Person对象
export function serializePerson(data) {
  return request({
    url: '/components/xmldecoder/serializePerson',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/json'
    }
  })
} 