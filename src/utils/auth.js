import Cookies from 'js-cookie'

const TokenKey = 'Authorization'
// const TokenKey = 'token'

// export function getToken() {
//   return Cookies.get(TokenKey)
// }

// export function setToken(token) {
//   return Cookies.set(TokenKey, token)
// }

// export function removeToken() {
//   return Cookies.remove(TokenKey)
// }

// 抛弃Cookie，改为使用localStorage
// 如果需要改回使用Cookie方式：1）注释下面代码，2）取消注释上面代码，3）修改user.js中的代码，取消注释行：// setToken(data)
export function getToken() {
  return localStorage.getItem(TokenKey)
}

export function setToken(token) {
  return localStorage.setItem(TokenKey, token)
}

export function removeToken() {
  return localStorage.removeItem(TokenKey)
}
