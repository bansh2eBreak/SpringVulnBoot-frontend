import request from '@/utils/request'

/**
 * 查询商品目录（含真实价格）
 */
export function getGoods() {
  return request({
    url: '/cryptoSecurity/frontendSign/goods',
    method: 'get'
  })
}

/**
 * 漏洞版下单：验签通过后直接信任前端 price
 * @param {Object} data { goodsId, price, count, sign }
 */
export function createOrderVuln(data) {
  return request({
    url: '/cryptoSecurity/frontendSign/vuln/order',
    method: 'post',
    data
  })
}

/**
 * 安全版下单：验签通过后忽略前端 price，按服务端真实价格计费
 * @param {Object} data { goodsId, price, count, sign }
 */
export function createOrderSec(data) {
  return request({
    url: '/cryptoSecurity/frontendSign/sec/order',
    method: 'post',
    data
  })
}
