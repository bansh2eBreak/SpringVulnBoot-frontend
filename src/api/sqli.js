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

// 报错注入相关接口
export function getUserByUsernameError(params) {
  return request({
    url: '/sqli/error/getUserByUsernameError',
    method: 'get',
    params: params
  })
}

export function getUserByIdError(params) {
  return request({
    url: '/sqli/error/getUserByIdError',
    method: 'get',
    params: params
  })
}

export function getUserCountError(params) {
  return request({
    url: '/sqli/error/getUserCountError',
    method: 'get',
    params: params
  })
}

// 新增：报错注入专用安全接口
export function getUserSecByUsernameErrorApi(params) {
  return request({
    url: '/sqli/error/getUserSecByUsername',
    method: 'get',
    params: params
  })
}

// 基于时间盲注相关接口
export function getUserByUsernameTime(params) {
  return request({
    url: '/sqli/time/getUserByUsernameTime',
    method: 'get',
    params: params
  })
}

export function getUserByUsernameTimeSafe(params) {
  return request({
    url: '/sqli/time/getUserByUsernameTimeSafe',
    method: 'get',
    params: params
  })
}

// UNION联合注入相关接口 - JDBC版本
export function getArticleVulnJdbc(params) {
  return request({
    url: '/sqli/union/getArticleVuln',
    method: 'get',
    params: params
  })
}

export function getArticleSecJdbc(params) {
  return request({
    url: '/sqli/union/getArticleSec',
    method: 'get',
    params: params
  })
}

// UNION联合注入相关接口 - MyBatis版本
export function getArticleVulnMybatis(params) {
  return request({
    url: '/sqli/union/mybatis/getArticleVuln',
    method: 'get',
    params: params
  })
}

export function getArticleSecMybatis(params) {
  return request({
    url: '/sqli/union/mybatis/getArticleSec',
    method: 'get',
    params: params
  })
}

// 布尔盲注相关接口 - JDBC版本
export function checkUserExistsVulnJdbc(params) {
  return request({
    url: '/sqli/boolean/jdbc/checkUserExistsVuln',
    method: 'get',
    params: params
  })
}

export function checkUserExistsSecJdbc(params) {
  return request({
    url: '/sqli/boolean/jdbc/checkUserExistsSec',
    method: 'get',
    params: params
  })
}

// 布尔盲注相关接口 - MyBatis版本
export function checkUserExistsVulnMybatis(params) {
  return request({
    url: '/sqli/boolean/mybatis/checkUserExistsVuln',
    method: 'get',
    params: params
  })
}

export function checkUserExistsSecMybatis(params) {
  return request({
    url: '/sqli/boolean/mybatis/checkUserExistsSec',
    method: 'get',
    params: params
  })
}
