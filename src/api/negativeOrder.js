import request from '@/utils/request'

function order(scene, quantity) {
  return request({
    url: '/businessLogic/negativeOrder/' + scene + '/order',
    method: 'post',
    data: { quantity }
  })
}

function status(scene) {
  return request({
    url: '/businessLogic/negativeOrder/' + scene + '/status',
    method: 'get'
  })
}

export function orderNormal(quantity) {
  return order('normal', quantity)
}

export function orderVuln(quantity) {
  return order('vuln', quantity)
}

export function orderSec(quantity) {
  return order('sec', quantity)
}

export function negativeOrderStatusNormal() {
  return status('normal')
}

export function negativeOrderStatusVuln() {
  return status('vuln')
}

export function negativeOrderStatusSec() {
  return status('sec')
}

export function resetNegativeOrder() {
  return request({
    url: '/businessLogic/negativeOrder/reset',
    method: 'post'
  })
}
