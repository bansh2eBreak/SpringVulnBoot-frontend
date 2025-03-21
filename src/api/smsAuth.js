import request from '@/utils/request'

export function sendVuln1(data) {
  return request({
    url: '/authentication/smsBased/sendVuln1',
    method: 'post',
    data: data
  })
}

export function sendSafe1(data) {
  return request({
    url: '/authentication/smsBased/sendSafe1',
    method: 'post',
    data: data
  })
}


export function verifyVuln1(data) {
  return request({
    url: '/authentication/smsBased/verifyVuln1',
    method: 'post',
    data: data
  })
}

export function verifySafe1(data) {
  return request({
    url: '/authentication/smsBased/verifySafe1',
    method: 'post',
    data: data
  })
}