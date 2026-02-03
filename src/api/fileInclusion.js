import request from '@/utils/request'

/**
 * 上传文件
 */
export function uploadScript(formData) {
  return request({
    url: '/fileInclusion/upload',
    method: 'post',
    data: formData,
    headers: {
      'Content-Type': 'multipart/form-data'
    }
  })
}

/**
 * Groovy 脚本包含执行（漏洞版本）
 * 注意：这个接口返回HTML，不是JSON
 */
export function groovyIncludeVuln(params) {
  // 去除可能的双斜杠问题
  const baseUrl = process.env.VUE_APP_BASE_API.replace(/\/$/, '')
  const url = `/fileInclusion/groovy/vuln?file=${encodeURIComponent(params.file)}`
  const cmdParam = params.cmd ? `&cmd=${encodeURIComponent(params.cmd)}` : ''
  
  return fetch(baseUrl + url + cmdParam, {
    method: 'GET',
    credentials: 'include'
  })
}

/**
 * Groovy 脚本安全执行（安全版本）
 */
export function groovyIncludeSecure(params) {
  return request({
    url: '/fileInclusion/groovy/sec',
    method: 'get',
    params
  })
}

/**
 * 下载示例文件
 */
export function downloadExample(type) {
  // 去除可能的双斜杠问题
  const baseUrl = process.env.VUE_APP_BASE_API.replace(/\/$/, '')
  const url = `${baseUrl}/fileInclusion/downloadExample?type=${type}`
  
  // 创建隐藏的a标签下载
  const link = document.createElement('a')
  link.href = url
  link.download = 'shell.groovy'
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
}
