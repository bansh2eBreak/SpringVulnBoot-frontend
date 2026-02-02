import axios from 'axios'
import { MessageBox, Message } from 'element-ui'
import store from '@/store'
import { getToken } from '@/utils/auth'

// create an axios instance
const service = axios.create({
  baseURL: process.env.VUE_APP_BASE_API, // VUE_APP_BASE_API = 'http://127.0.0.1:8080/'
  withCredentials: true, // send cookies when cross-domain requests
  timeout: 5000 // request timeout
})

// request interceptor
service.interceptors.request.use(
  config => {
    // do something before request is sent
    if (store.getters.token) {
      // let each request carry token
      // ['X-Token'] is a custom headers key
      // please modify it according to the actual situation
      // config.headers['Authorization'] = getToken()
      config.headers['Authorization'] = localStorage.getItem('Authorization')
      // Credential: 'include'  // ❌ 已注释：这是语法错误（标签语句），不起作用
      // ✅ 正确方式：withCredentials 已在创建 axios 实例时设置（第9行），无需重复设置
      // 如果需要在特定请求中覆盖，使用：config.withCredentials = true
    }
    
    // 检查是否是JWT相关的请求，如果是则使用jwt token
    if (config.url && config.url.includes('jwt/')) {
      const jwtToken = localStorage.getItem('jwt')
      if (jwtToken) {
        config.headers['jwt'] = jwtToken
      }
    }
    
    return config
  },
  error => {
    // do something with request error
    console.log(error) // for debug
    return Promise.reject(error)
  }
)

// response interceptor
service.interceptors.response.use(
  /**
   * If you want to get http information such as headers or status
   * Please return  response => response
  */

  /**
   * Determine the request status by custom code
   * Here is just an example
   * You can also judge the status by HTTP Status Code
   */
  /** 
  response => {
    const res = response.data

    // if the custom code is not 20000, it is judged as an error.
    if (res.code !== 0) {
      Message({
        message: res.data || 'Error',
        type: 'error',
        duration: 5 * 1000
      })

      // // 50008: Illegal token; 50012: Other clients logged in; 50014: Token expired;
      // if (res.code === 50008 || res.code === 50012 || res.code === 50014) {
      //   // to re-login
      //   MessageBox.confirm('You have been logged out, you can cancel to stay on this page, or log in again', 'Confirm logout', {
      //     confirmButtonText: 'Re-Login',
      //     cancelButtonText: 'Cancel',
      //     type: 'warning'
      //   }).then(() => {
      //     store.dispatch('user/resetToken').then(() => {
      //       location.reload()
      //     })
      //   }) 
      // }
      return Promise.reject(new Error(res.msg || 'Error'))
    } else {
      return res
    }
  }, */
  response => {
    // 对于blob类型的响应，直接返回response对象
    if (response.config.responseType === 'blob') {
      return response
    }
    
    if (response.status === 200) {
      // HTTP状态码为200，表示请求成功
      try {
        // const res = JSON.parse(response.data) //response.data.data 是 jwttoken
        const res = response.data
        console.log("响应码："+res.code)
        // 优化，当返回的数据不是标准的json格式时，直接返回响应文本
        if (res.code !== undefined && res.code !== null) {
          if (res.code !== 0) {
            Message({
              message: res.data || 'Error',
              type: 'error',
              duration: 5 * 1000
            });
            return Promise.reject(new Error(res.msg || 'Error'));
          } else {
            return res;
          }
        } else {
          return res;
        }
      } catch (error) {
        // 如果无法解析为JSON，则将响应文本作为消息内容处理
        // response 内容不是标准的JSON格式
        Message({
          message: response.data || 'Error',
          type: 'error',
          duration: 5 * 1000
        })
        return Promise.reject(new Error('Error parsing response'))
      }
    } else {
      // 处理HTTP状态码不是200的情况
      // 在这里添加相应的处理逻辑
      Message({
        message: 'HTTP Error: ' + response.status,
        type: 'error',
        duration: 5 * 1000
      })
      return Promise.reject(new Error('HTTP Error'))
    }
  },
  error => {
    Message({
      message: error.message,
      type: 'error',
      duration: 5 * 1000
    })
    return Promise.reject(error)
  }
)

export default service
