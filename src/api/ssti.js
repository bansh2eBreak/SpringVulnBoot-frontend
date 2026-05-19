import { getBaseUrl } from '@/utils/request'

/**
 * 构建 SSTI 漏洞演示的完整 URL
 *
 * @param {String} scene - 场景：'vuln' | 'sec/whitelist' | 'sec/model'
 * @param {String} lang  - lang 参数（用户输入，可能含 SSTI payload）
 * @returns {String} 完整可读的 URL（含 baseURL）
 */
export function buildSstiUrl(scene, lang) {
  const baseUrl = getBaseUrl()
  return `${baseUrl}/ssti/${scene}?lang=${encodeURIComponent(lang)}`
}

/**
 * 拉取 SSTI 接口返回的 HTML 内容
 * 由前端通过 iframe.srcdoc 渲染，避免被 X-Frame-Options: DENY 拦截
 * 设置 Accept: text/html 确保错误页面也返回 HTML 格式（Whitelabel Error Page）
 */
export function fetchSstiHtml(scene, lang) {
  const url = buildSstiUrl(scene, lang)
  return fetch(url, {
    method: 'GET',
    credentials: 'include',
    headers: { 'Accept': 'text/html' }
  })
}
