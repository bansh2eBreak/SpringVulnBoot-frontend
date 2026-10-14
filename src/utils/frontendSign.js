import CryptoJS from 'crypto-js'

/**
 * 前端加签工具（前端加签被逆向漏洞演示）
 *
 * ❌ 漏洞根源：加签密钥 SIGN_SECRET 硬编码在前端 JS 中。
 *    前端要算 sign 就必须持有 secret，而前端代码会下发到用户浏览器，
 *    任何人打开 F12 / 逆向打包后的 JS 都能拿到这个 secret 和拼接规则，
 *    从而伪造任意合法签名（如把 price 改成 1 后重新算出后端认可的 sign）。
 *
 * 这个 SIGN_SECRET 与后端 FrontendSignController.SIGN_SECRET 完全一致。
 */
export const SIGN_SECRET = 'x9f2Kd8sLp3qW7mE'

/**
 * 计算签名：sign = md5(参数按 key 升序拼接 "k=v&..." + SIGN_SECRET)
 * @param {Object} params 参与签名的参数（如 { goodsId, price, count }）
 * @returns {string} 32 位小写十六进制 MD5
 */
export function buildSign(params) {
  const raw = Object.keys(params)
    .sort()
    .map(k => `${k}=${params[k]}`)
    .join('&') + SIGN_SECRET
  return CryptoJS.MD5(raw).toString()
}

/**
 * 构造带签名的下单请求体
 * @param {Object} params { goodsId, price, count }
 * @returns {Object} { goodsId, price, count, sign }
 */
export function buildSignedOrder(params) {
  return { ...params, sign: buildSign(params) }
}
