/**
 * Created by PanJiaChen on 16/11/18.
 */

/**
 * @param {string} path
 * @returns {Boolean}
 */
export function isExternal(path) {
  return /^(https?:|mailto:|tel:)/.test(path)
}

/**
 * @param {string} str
 * @returns {Boolean}
 */
/**
 * 验证用户名格式
 * 只验证格式，不验证用户名是否存在（由后端验证）
 */
export function validUsername(str) {
  // 移除硬编码的用户名白名单
  // 只要用户名不为空即可，具体是否有效由后端验证
  return str && str.trim().length > 0
}
