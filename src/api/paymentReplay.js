import request from '@/utils/request'

export function createRechargeOrder() {
  return request({
    url: '/businessLogic/paymentReplay/order/create',
    method: 'post'
  })
}

export function notifyPayment(mode, order) {
  return request({
    url: '/businessLogic/paymentReplay/' + mode + '/notify',
    method: 'post',
    data: {
      rechargeNo: order.rechargeNo,
      gatewayTransactionNo: order.gatewayTransactionNo
    }
  })
}

export function paymentReplayStatus() {
  return request({
    url: '/businessLogic/paymentReplay/status',
    method: 'get'
  })
}

export function resetPaymentReplay() {
  return request({
    url: '/businessLogic/paymentReplay/reset',
    method: 'post'
  })
}
