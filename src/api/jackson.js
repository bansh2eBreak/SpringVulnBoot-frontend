import request from '@/utils/request'

// Jackson基础功能 - 序列化Person对象
export function serializePersonToJson(data) {
  return request({
    url: '/components/jackson/serializePersonToJson',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'application/json'
    }
  })
}

// Jackson基础功能 - 反序列化Person对象
export function deserializePersonFromJson(data) {
  return request({
    url: '/components/jackson/deserializePersonFromJson',
    method: 'post',
    data: data,
    headers: {
      'Content-Type': 'text/plain'
    }
  })
}


