import request from '@/utils/request'

// 反序列化漏洞相关API
export function serializePerson(data) {
  return request({
    url: '/deserialize/serializePerson',
    method: 'post',
    data,
    responseType: 'blob'
  })
}

export function deserializePerson(data) {
  return request({
    url: '/deserialize/deserializePerson',
    method: 'post',
    headers: {
      'Content-Type': 'multipart/form-data'
    },
    data
  })
}

export function serializeBadPerson(data) {
  return request({
    url: '/deserialize/serializeBadPerson',
    method: 'post',
    data,
    responseType: 'blob'
  })
}

export function deserializeBadPerson(data) {
  return request({
    url: '/deserialize/deserializeBadPerson',
    method: 'post',
    headers: {
      'Content-Type': 'multipart/form-data'
    },
    data
  })
}

export function base64Deserialize(data) {
  return request({
    url: '/deserialize/base64Deserialize',
    method: 'post',
    headers: {
      'Content-Type': 'text/plain'
    },
    data
  })
}

export function secureDeserialize(data) {
  return request({
    url: '/deserialize/secureDeserialize',
    method: 'post',
    headers: {
      'Content-Type': 'text/plain'
    },
    data
  })
}



export function serializeURLDNS(data) {
  return request({
    url: '/deserialize/serializeURLDNS',
    method: 'post',
    data,
    responseType: 'blob'
  })
}

export function deserializeURLDNS(data) {
  return request({
    url: '/deserialize/deserializeURLDNS',
    method: 'post',
    headers: {
      'Content-Type': 'multipart/form-data'
    },
    data
  })
} 