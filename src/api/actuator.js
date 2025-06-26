import request from '@/utils/request'

// 获取环境变量信息
export function getEnvInfo() {
  return request({
    url: '/actuator/env',
    method: 'get'
  })
}

// 获取配置属性信息
export function getConfigProps() {
  return request({
    url: '/actuator/configprops',
    method: 'get'
  })
}

// 获取健康检查信息
export function getHealthInfo() {
  return request({
    url: '/actuator/health',
    method: 'get'
  })
}

// 获取应用指标信息
export function getMetricsInfo() {
  return request({
    url: '/actuator/metrics',
    method: 'get'
  })
} 