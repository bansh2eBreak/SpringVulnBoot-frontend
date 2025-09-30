import request from '@/utils/request'

// IP地址伪造漏洞测试接口
export function testIpSpoofingVuln(user, headers = {}) {
  return request({
    url: '/ipspoofing/vuln',
    method: 'post',
    data: user,
    headers: headers
  })
}

// 安全IP获取测试接口
export function testIpSpoofingSec(user, headers = {}) {
  return request({
    url: '/ipspoofing/sec',
    method: 'post',
    data: user,
    headers: headers
  })
}

// 正常登录接口
export function normalLogin(data) {
  return request({
    url: '/ipspoofing/login',
    method: 'post',
    data: data
  })
}

// 查询所有用户登录日志接口
export function getAllUserLoginLogs() {
  return request({
    url: '/ipspoofing/logs',
    method: 'get'
  })
}
