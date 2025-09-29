import request from '@/utils/request'

// ReDoS漏洞测试接口
export function testReDoS(input) {
  return request({
    url: '/redos/vuln',
    method: 'post',
    data: {
      input: input
    }
  })
}

// 安全正则表达式测试接口
export function testSafeRegex(input) {
  return request({
    url: '/redos/sec',
    method: 'post',
    data: {
      input: input
    }
  })
}
