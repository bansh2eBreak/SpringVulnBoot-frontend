import request from '@/utils/request'

export function queryMessage() {
  return request({
    url: '/xss/stored/queryMessage',
    method: 'get'
  })
}

export function addMessage(data) {
  return request({
    url: '/xss/stored/addMessage',
    method: 'post',
    data: data
  })
}

export function addMessageSec(data) {
  return request({
    url: '/xss/stored/addMessageSec',
    method: 'post',
    data: data
  })
}

export function vuln1(params) {
  return request({
    url: '/xss/reflected/vuln1',
    method: 'get',
    params: params
  })
}

export function sec1(params) {
  return request({
    url: '/xss/reflected/sec1',
    method: 'get',
    params: params
  })
}

export function sec2(params) {
  return request({
    url: '/xss/reflected/sec2',
    method: 'get',
    params: params
  })
}

export function sec3(params) {
  return request({
    url: '/xss/reflected/sec3',
    method: 'get',
    params: params
  })
}