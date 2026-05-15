import request, { getBaseUrl } from '@/utils/request'

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
  const baseUrl = getBaseUrl()
  const url = `/fileInclusion/groovy/vuln?file=${encodeURIComponent(params.file)}`
  const cmdParam = params.cmd ? `&cmd=${encodeURIComponent(params.cmd)}` : ''

  return fetch(baseUrl + url + cmdParam, {
    method: 'GET',
    credentials: 'include'
  })
}

/**
 * Groovy 脚本安全执行（安全版本）
 * 注意：这个接口返回HTML，不是JSON
 */
export function groovyIncludeSecure(params) {
  const baseUrl = getBaseUrl()
  const url = `/fileInclusion/groovy/sec?file=${encodeURIComponent(params.file)}`
  const cmdParam = params.cmd ? `&cmd=${encodeURIComponent(params.cmd)}` : ''

  return fetch(baseUrl + url + cmdParam, {
    method: 'GET',
    credentials: 'include'
  })
}

/**
 * 下载示例文件
 */
export function downloadExample(type) {
  const baseUrl = getBaseUrl()
  const url = `${baseUrl}/fileInclusion/downloadExample?type=${type}`
  
  // 创建隐藏的a标签下载
  const link = document.createElement('a')
  link.href = url
  link.download = 'shell.groovy'
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
}
