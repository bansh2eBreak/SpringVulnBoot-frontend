import request from '@/utils/request'

export function vuln1(data) {
  return request({
    url: '/authentication/passwordBased/vuln1',
    method: 'post',
    data: data
  })
}

export function vuln2(data, headers = {}) {
  return request({
    url: '/authentication/passwordBased/vuln2',
    method: 'post',
    headers: headers,
    data: data
  })
}

export function sec(data) {
  return request({
    url: '/authentication/passwordBased/sec',
    method: 'post',
    data: data
  })
}

export function httpBasicLogin(headers = {}) {
  return request({
    url: '/authentication/passwordBased/httpBasicLogin',
    method: 'post',
    headers: headers
  })
}

export function captcha() {
  return request({
    url: '/authentication/passwordBased/captcha',
    method: 'get'
  })
}

export function vuln3(data) {
  const formData = `username=${data.username}&password=${data.password}&captcha=${data.captcha}`;

  return request({
    url: '/authentication/passwordBased/vuln3',
    method: 'post',
    data: formData, // 使用 FormData 传递参数
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    }
  })
}

export function sec2(data) {
  const formData = `username=${data.username}&password=${data.password}&captcha=${data.captcha}`;

  return request({
    url: '/authentication/passwordBased/sec2',
    method: 'post',
    data: formData, // 使用 FormData 传递参数
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    }
  })
}

// export function sec2(data) {
//   const formData = new FormData();
//   formData.append('username', data.username);
//   formData.append('password', data.password);
//   formData.append('captcha', data.captcha);

//   return request({
//     url: '/authentication/passwordBased/sec2',
//     method: 'post',
//     data: formData // 使用 FormData 传递参数
//   })
// }

