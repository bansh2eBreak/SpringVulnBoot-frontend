import { getBaseUrl } from '@/utils/request'

const baseURL = getBaseUrl()

/**
 * 构造 CRLF 注入测试 URL
 * @param {string} scene - 'vuln' 或 'sec'
 * @param {string} input - 用户输入（已包含真实 \r\n）
 * @returns {string} 完整 URL
 */
export function buildCrlfUrl(scene, input) {
  return `${baseURL}/crlf/${scene}?input=${encodeURIComponent(input)}`
}
