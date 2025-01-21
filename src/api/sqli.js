import request from '@/utils/request'

export function getUserByUsername(params) {
  return request({
    url: '/sqli/jdbc/getUserByUsername',
    method: 'get',
    params: params
  })
}

export function getUserByPage(params) {
  return request({
    url: '/sqli/mybatis/getUserByPage',
    method: 'get',
    params: params
  })
}

export function getUserByUsernameFilter(params) {
  return request({
    url: '/sqli/jdbc/getUserSecByUsernameFilter',
    method: 'get',
    params: params
  })
}

export function getUserSecByUsernameError(params) {
  return request({
    url: '/sqli/jdbc/getUserSecByUsernameError',
    method: 'get',
    params: params
  })
}

export function getUserSecByUsername(params) {
  return request({
    url: '/sqli/jdbc/getUserSecByUsername',
    method: 'get',
    params: params
  })
}

export function getUserById(params) {
  return request({
    url: '/sqli/mybatis/getUserById',
    method: 'get',
    params: params
  })
}

export function getUserByIdSec(params) {
  return request({
    url: '/sqli/mybatis/getUserByIdSec',
    method: 'get',
    params: params
  })
}

export function getUserSecByUsername2(params) {
  return request({
    url: '/sqli/mybatis/getUserSecByUsername2',
    method: 'get',
    params: params
  })
}
