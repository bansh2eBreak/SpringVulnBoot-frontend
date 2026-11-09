import request from '@/utils/request'

const campaignCode = 'NEWUSER-10'

export function claimCouponNormal() {
  return request({
    url: '/businessLogic/couponRace/normal/claim',
    method: 'post',
    data: { campaignCode }
  })
}

export function couponStatusNormal() {
  return request({
    url: '/businessLogic/couponRace/normal/status',
    method: 'get'
  })
}

export function claimCouponVuln() {
  return request({
    url: '/businessLogic/couponRace/vuln/claim',
    method: 'post',
    data: { campaignCode }
  })
}

export function couponStatusVuln() {
  return request({
    url: '/businessLogic/couponRace/vuln/status',
    method: 'get'
  })
}

export function claimCouponSec() {
  return request({
    url: '/businessLogic/couponRace/sec/claim',
    method: 'post',
    data: { campaignCode }
  })
}

export function couponStatusSec() {
  return request({
    url: '/businessLogic/couponRace/sec/status',
    method: 'get'
  })
}

export function resetCouponRace() {
  return request({
    url: '/businessLogic/couponRace/reset',
    method: 'post',
    data: { campaignCode }
  })
}
