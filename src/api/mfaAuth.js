import request from '@/utils/request'

export function bindMfa(data) {
  return request({
    url: '/accessControl/HorizontalPri/bindMfa',
    method: 'post',
    data: data
  })
}

export function resetMfa(data) {
  return request({
    url: '/accessControl/HorizontalPri/resetMfa',
    method: 'post',
    data: data
  })
}

