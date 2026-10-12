<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">种子可预测漏洞（密码重置 token 可预测 → 账户接管）</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              <strong>种子可预测漏洞</strong>是指应用使用<strong>不安全的随机数生成器</strong>（如 Java 的 <code>java.util.Random</code> / <code>Math.random()</code>）生成安全敏感的值（密码重置 token、验证码、会话 ID 等），导致攻击者可以<strong>预测</strong>这些值。
              <br /><br />
              <span style="color: red;">根因：java.util.Random 不是真随机</span>
              <br />
              <code>java.util.Random</code> 本质是<strong>线性同余生成器（LCG）</strong>，是一个完全确定的数学公式：
              <pre style="background:#f5f5f5;padding:10px;border-radius:4px;margin:8px 0;color:#333;">seed = (seed * 0x5DEECE66D + 0xB) &amp; ((1 &lt;&lt; 48) - 1);
return (int)(seed >>> (48 - bits));</pre>
              三个致命点：① 种子只有 48 位；② 递推常量公开写死在 JDK；③ <strong>知道种子 = 知道全部后续输出</strong>。
              <br /><br />
              <span style="color: red;">本场景的漏洞写法：</span>
              <pre style="background:#f5f5f5;padding:10px;border-radius:4px;margin:8px 0;color:#333;">long seed = System.currentTimeMillis();        // ❌ 种子 = 毫秒时间戳
String token = Long.toHexString(new Random(seed).nextLong());</pre>
              开发者以为"时间戳每毫秒都不同，够随机了"，但<strong>时间戳不是秘密</strong>——HTTP 响应的 <code>Date</code> 头就把服务器时间泄露到了<strong>秒级</strong>。
              <br /><br />
              <span style="color: red;">攻击链（方式二：在线爆破）：</span>
              <br />
              ① 攻击者对<strong>受害人账号</strong>发起"忘记密码"，后端用 <code>new Random(当前毫秒)</code> 生成 token 发往受害人邮箱<br />
              ② 后端响应（或 Date 头）暴露<strong>秒级</strong>服务器时间，那一秒内只有 <strong>1000 个</strong>毫秒候选种子<br />
              ③ 攻击者在<strong>浏览器里复刻 java.util.Random</strong>，枚举这 1000 个种子，本地算出 1000 个候选 token<br />
              ④ 用这 1000 个候选 token <strong>在线爆破</strong> <code>/reset</code> 接口（模拟 Burp Intruder），命中即接管
              <br /><br />
              <span style="color: #e6a23c; font-weight: bold;">⚠️ 与 Host Header 投毒的区别：</span>
              <br />
              Host Header 投毒需要把 token "骗"到攻击者服务器；而本漏洞<strong>根本不用骗</strong>——token 可以直接用数学算出来。即使 token 安全发送给受害人，攻击者也能预测。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              可预测随机数会让一切"依赖不可预测性"的安全机制失效：
              <br /><br />
              <span style="color: red;">主要危害：</span>
              <br />
              • <strong>账户接管</strong>：预测密码重置 token / 邮箱验证 token，直接重置他人密码
              <br />
              • <strong>会话劫持</strong>：预测 Session ID，冒充已登录用户
              <br />
              • <strong>验证码爆破</strong>：预测短信/邮箱验证码，绕过二次验证
              <br />
              • <strong>优惠券/抽奖作弊</strong>：预测优惠券码、中奖序列号
              <br />
              • <strong>CSRF token 绕过</strong>：预测 CSRF token，使防护形同虚设
              <br /><br />
              <span style="color: red;">真实案例：</span>
              <br />
              • 大量 Java 应用误用 <code>java.util.Random</code> 生成 token（CWE-330 / CWE-338）
              <br />
              • Jenkins、多个 CMS 曾因可预测 token 被账户接管
              <br />
              • Hacker One 上"predictable password reset token"是高频高奖金报告类型
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <span style="color: red;">【必须】使用 SecureRandom 生成安全敏感的随机值</span>
              <br />
              所有 token、密码、盐、会话 ID、验证码必须用 <code>java.security.SecureRandom</code>（从操作系统熵池取种子，状态不可预测）：
              <pre style="background:#f5f5f5;padding:10px;border-radius:4px;margin:8px 0;color:#333;">SecureRandom sr = new SecureRandom();
byte[] buf = new byte[32];
sr.nextBytes(buf);
String token = Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
// 或直接用 UUID.randomUUID()（底层即 SecureRandom）</pre>
              <span style="color: red;">【禁止】用 java.util.Random / Math.random() 做安全用途</span>
              <br />
              它们只适合做"非安全"的随机（如打乱列表、游戏掉落），<strong>绝不能</strong>用于安全场景。
              <br /><br />
              <span style="color: red;">【禁止】用时间戳 / 自增 ID / 用户信息当种子或 token</span>
              <br />
              任何"可被外部观测或推算"的值都不能作为随机性来源。
              <br /><br />
              <span style="color: red;">【建议】token 足够长 + 一次性 + 设置有效期</span>
              <br />
              即便用了 SecureRandom，也应保证 token 长度足够（≥128 bit）、用后即失效、限制有效期，并对 <code>/reset</code> 接口做限流，降低在线爆破可行性。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://cwe.mitre.org/data/definitions/330.html" target="_blank" style="text-decoration: underline;">《CWE-330: Use of Insufficiently Random Values》</a>：CWE 对弱随机值的分类描述。<br />
              <a href="https://cwe.mitre.org/data/definitions/338.html" target="_blank" style="text-decoration: underline;">《CWE-338: Use of Cryptographically Weak PRNG》</a>：密码学弱 PRNG。<br />
              <a href="https://owasp.org/www-community/vulnerabilities/Insecure_Randomness" target="_blank" style="text-decoration: underline;">《OWASP - Insecure Randomness》</a>：OWASP 对不安全随机数的说明。<br />
              <a href="https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/SecureRandom.html" target="_blank" style="text-decoration: underline;">《Java SecureRandom 官方文档》</a>：安全随机数 API。<br />
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </div>

    <div class="code-demo">
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 - java.util.Random + 时间戳种子
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * 种子可预测 - 漏洞版
 * 用 java.util.Random（LCG）+ 毫秒时间戳种子生成 token
 */
@PostMapping("/forgot-password/vuln")
public Result forgotPasswordVuln(
        @RequestBody Map&lt;String, String&gt; body) {
    String username = body.get("username");

    // ❌ 种子 = 毫秒时间戳，可预测
    long seed = System.currentTimeMillis();
    long raw = new Random(seed).nextLong();
    String token = Long.toHexString(raw);

    RESET_TOKENS.put(token, username);

    // 仅返回秒级时间（模拟 Date 头），不返回 token
    long second = (seed / 1000L) * 1000L;
    return Result.success(buildMail(username, second));
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - SecureRandom
              <el-button type="success" round size="mini" @click="showSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * 种子可预测 - 安全版
 * 用 SecureRandom 生成不可预测 token
 */
private static final SecureRandom SECURE_RANDOM
        = new SecureRandom();

@PostMapping("/forgot-password/sec")
public Result forgotPasswordSec(
        @RequestBody Map&lt;String, String&gt; body) {
    String username = body.get("username");

    // ✅ SecureRandom：从 OS 熵池取随机，不可预测
    long raw = SECURE_RANDOM.nextLong();
    String token = Long.toHexString(raw);

    RESET_TOKENS.put(token, username);
    long second = (System.currentTimeMillis() / 1000L) * 1000L;
    return Result.success(buildMail(username, second));
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <!-- 漏洞版测试对话框 -->
    <el-dialog title="种子可预测漏洞测试（在线爆破）" :visible.sync="vulnDialogVisible" class="center-dialog" width="880px" @close="resetVulnState">
      <div style="text-align: left; color: red; font-style: italic;">
        本测试模拟攻击者预测密码重置 token 并在线爆破（类似 Burp Suite Intruder）接管 admin 账号。
      </div>
      <!-- Step 1 -->
      <div class="step-block">
        <div class="step-title"><span class="step-num">1</span> 攻击者触发"给受害人发重置邮件"</div>
        <div class="step-desc">
          后端用 <code>new Random(System.currentTimeMillis())</code> 生成 token 发往受害人邮箱，
          只把<strong>秒级</strong>服务器时间返回给我们（模拟 HTTP Date 头）。
        </div>
        <el-input v-model="vulnForm.username" placeholder="目标用户名" style="width: 240px; margin-right: 10px;">
          <template #prepend>username</template>
        </el-input>
        <el-button type="primary" :loading="vulnForm.loading1" @click="step1Trigger">发起重置</el-button>

        <div v-if="vulnForm.serverTimeSecond" class="info-box">
          <div>📧 token 已发往：<b>{{ vulnForm.victimEmail }}</b>（攻击者收不到）</div>
          <div>🕒 服务器秒级时间：<code>{{ vulnForm.serverTimeSecond }}</code>（<code>{{ formatTime(vulnForm.serverTimeSecond) }}</code>）</div>
          <div>🔢 候选种子范围：<code>{{ vulnForm.serverTimeSecond }}</code> ~ <code>{{ vulnForm.serverTimeSecond + 999 }}</code>（共 1000 个）</div>
        </div>
      </div>

      <!-- Step 2 -->
      <div class="step-block">
        <div class="step-title"><span class="step-num">2</span> 本地复刻 Java Random，生成候选 token</div>
        <div class="step-desc">
          在浏览器里枚举这 1000 个毫秒种子，用复刻的 <code>java.util.Random</code> 算出 1000 个候选 token。
        </div>
        <el-button type="primary" :disabled="!vulnForm.serverTimeSecond" @click="step2GenCandidates">生成 1000 个候选 token</el-button>
        <div v-if="vulnForm.candidates.length" class="info-box">
          ✅ 已生成 <b>{{ vulnForm.candidates.length }}</b> 个候选 token，示例（前 3 个）：
          <pre class="sample-pre">{{ candidateSample }}</pre>
        </div>
      </div>

      <!-- Step 3 -->
      <div class="step-block">
        <div class="step-title"><span class="step-num">3</span> Intruder 在线爆破 /reset</div>
        <div class="step-desc">
          对 1000 个候选 token 逐个打 <code>/reset</code>（每批 20 并发），命中即接管。
          新密码：<code>{{ newPassword }}</code>
        </div>
        <el-button type="danger" :disabled="!vulnForm.candidates.length || vulnForm.attacking" :loading="vulnForm.attacking" @click="step3BruteForce">
          {{ vulnForm.attacking ? '爆破中...' : '开始爆破' }}
        </el-button>

        <div v-if="vulnForm.attacking || vulnForm.attackDone" style="margin-top: 12px;">
          <el-progress :percentage="vulnForm.progress" :status="vulnForm.hit ? 'success' : undefined" />
          <div class="brute-stat">
            已尝试 <b>{{ vulnForm.tried }}</b> / {{ vulnForm.candidates.length }}
            ｜ 失败 <b>{{ vulnForm.failCount }}</b>
            ｜ 命中 <b :style="{color: vulnForm.hit ? '#67c23a' : '#909399'}">{{ vulnForm.hit ? 1 : 0 }}</b>
          </div>
        </div>

        <div v-if="vulnForm.hit" class="result-box result-success" style="margin-top: 12px;">
          🎯 <b>爆破命中！账户接管成功</b><br>
          命中候选：第 <b>{{ vulnForm.hitIndex + 1 }}</b> 个（种子 <code>{{ vulnForm.hitSeed }}</code>）<br>
          命中 token：<code>{{ vulnForm.hitToken }}</code><br>
          后端响应：{{ vulnForm.hitMsg }}
        </div>
        <div v-else-if="vulnForm.attackDone" class="result-box result-warning" style="margin-top: 12px;">
          未命中（漏洞版正常情况下应当命中，请检查后端是否为漏洞版接口/时间是否漂移）。
        </div>
      </div>

      <!-- Step 4 -->
      <div class="step-block">
        <div class="step-title"><span class="step-num">4</span> 验证账号已被接管</div>
        <div class="step-desc">
          回到靶场 → 退出 → 用 <code>admin / {{ newPassword }}</code> 登录成功即闭环完成。
          <br><strong>恢复方法：</strong>登录后到"个人中心"将密码改回原值。
        </div>
      </div>
    </el-dialog>

    <!-- 安全版测试对话框 -->
    <el-dialog title="种子可预测安全版测试" :visible.sync="secDialogVisible" class="center-dialog" width="880px" @close="resetSecState">
      <div style="text-align: left; color: green; font-style: italic;">
        安全版用 <code>SecureRandom</code> 生成 token，与时间戳无关，无法通过枚举种子预测，爆破必然失败。
      </div>
      <br />

      <div class="step-block">
        <div class="step-title"><span class="step-num">1</span> 触发重置（安全版）</div>
        <el-input v-model="secForm.username" placeholder="目标用户名" style="width: 240px; margin-right: 10px;">
          <template #prepend>username</template>
        </el-input>
        <el-button type="primary" :loading="secForm.loading1" @click="secStep1">发起重置</el-button>
        <div v-if="secForm.serverTimeSecond" class="info-box">
          🕒 秒级时间：<code>{{ secForm.serverTimeSecond }}</code> ｜ token 由 SecureRandom 生成
        </div>
      </div>

      <div class="step-block">
        <div class="step-title"><span class="step-num">2</span> 同样枚举 1000 候选并爆破</div>
        <el-button type="warning" :disabled="!secForm.serverTimeSecond || secForm.attacking" :loading="secForm.attacking" @click="secBruteForce">
          {{ secForm.attacking ? '爆破中...' : '生成候选并爆破' }}
        </el-button>
        <div v-if="secForm.attacking || secForm.attackDone" style="margin-top: 12px;">
          <el-progress :percentage="secForm.progress" />
          <div class="brute-stat">已尝试 <b>{{ secForm.tried }}</b> / 1000 ｜ 失败 <b>{{ secForm.failCount }}</b> ｜ 命中 <b>0</b></div>
        </div>
        <div v-if="secForm.attackDone" class="result-box result-success" style="margin-top: 12px;">
          ✅ <b>1000 个候选全部失败</b>，SecureRandom 不可预测，攻击无法成立。
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { forgotPasswordVuln, forgotPasswordSec, resetPassword } from '@/api/predictableSeed'
import { generateCandidateTokens } from '@/utils/javaRandom'

const CONCURRENCY = 20
const NEW_PASSWORD = 'hacked_by_predictable_seed'

export default {
  name: 'PredictableSeed',
  data() {
    return {
      activeName: 'first',
      vulnDialogVisible: false,
      secDialogVisible: false,
      newPassword: NEW_PASSWORD,
      vulnForm: this.initVulnForm(),
      secForm: this.initSecForm()
    }
  },
  computed: {
    candidateSample() {
      return this.vulnForm.candidates.slice(0, 3)
        .map(c => `seed=${c.seed}  ->  ${c.token}`)
        .join('\n')
    }
  },
  methods: {
    initVulnForm() {
      return {
        username: 'admin',
        loading1: false,
        victimEmail: '',
        serverTimeSecond: 0,
        candidates: [],
        attacking: false,
        attackDone: false,
        progress: 0,
        tried: 0,
        failCount: 0,
        hit: false,
        hitIndex: -1,
        hitSeed: 0,
        hitToken: '',
        hitMsg: ''
      }
    },
    initSecForm() {
      return {
        username: 'admin',
        loading1: false,
        serverTimeSecond: 0,
        attacking: false,
        attackDone: false,
        progress: 0,
        tried: 0,
        failCount: 0
      }
    },
    handleClick() {},
    showVulnDialog() { this.vulnDialogVisible = true },
    showSecDialog() { this.secDialogVisible = true },
    resetVulnState() { this.vulnForm = this.initVulnForm() },
    resetSecState() { this.secForm = this.initSecForm() },

    formatTime(ms) {
      const d = new Date(Number(ms))
      return d.toLocaleString()
    },

    async step1Trigger() {
      if (!this.vulnForm.username) {
        this.$message.warning('请填写用户名')
        return
      }
      this.vulnForm.loading1 = true
      try {
        const res = await forgotPasswordVuln(this.vulnForm.username)
        this.vulnForm.serverTimeSecond = res.data.serverTimeSecond
        this.vulnForm.victimEmail = res.data.to
        this.vulnForm.candidates = []
        this.vulnForm.attackDone = false
        this.vulnForm.hit = false
        this.$message.success('已触发重置，获得秒级服务器时间')
      } catch (e) {
        this.$message.error('请求失败：' + e.message)
      } finally {
        this.vulnForm.loading1 = false
      }
    },

    step2GenCandidates() {
      this.vulnForm.candidates = generateCandidateTokens(this.vulnForm.serverTimeSecond)
      this.$message.success(`已生成 ${this.vulnForm.candidates.length} 个候选 token`)
    },

    async step3BruteForce() {
      const candidates = this.vulnForm.candidates
      if (!candidates.length) return

      this.vulnForm.attacking = true
      this.vulnForm.attackDone = false
      this.vulnForm.progress = 0
      this.vulnForm.tried = 0
      this.vulnForm.failCount = 0
      this.vulnForm.hit = false

      try {
        await this.runIntruder(candidates, this.vulnForm, true)
      } finally {
        this.vulnForm.attacking = false
        this.vulnForm.attackDone = true
      }
    },

    async secStep1() {
      if (!this.secForm.username) {
        this.$message.warning('请填写用户名')
        return
      }
      this.secForm.loading1 = true
      try {
        const res = await forgotPasswordSec(this.secForm.username)
        this.secForm.serverTimeSecond = res.data.serverTimeSecond
        this.secForm.attackDone = false
        this.$message.success('已触发重置（安全版）')
      } catch (e) {
        this.$message.error('请求失败：' + e.message)
      } finally {
        this.secForm.loading1 = false
      }
    },

    async secBruteForce() {
      const candidates = generateCandidateTokens(this.secForm.serverTimeSecond)
      this.secForm.attacking = true
      this.secForm.attackDone = false
      this.secForm.progress = 0
      this.secForm.tried = 0
      this.secForm.failCount = 0
      try {
        await this.runIntruder(candidates, this.secForm, false)
      } finally {
        this.secForm.attacking = false
        this.secForm.attackDone = true
      }
    },

    /**
     * 模拟 Burp Intruder：分批并发爆破 /reset
     * @param candidates 候选 {seed, token}
     * @param state 响应式状态对象（vulnForm / secForm）
     * @param stopOnHit 命中是否立即停止
     */
    async runIntruder(candidates, state, stopOnHit) {
      const total = candidates.length
      let index = 0
      let stopped = false

      while (index < total && !stopped) {
        const batch = candidates.slice(index, index + CONCURRENCY)
        const results = await Promise.all(batch.map(async (c, i) => {
          try {
            const res = await resetPassword(c.token, NEW_PASSWORD)
            return { ok: res.code === 0, candidate: c, globalIndex: index + i, msg: res.data || res.msg }
          } catch (e) {
            return { ok: false, candidate: c, globalIndex: index + i, msg: e.message }
          }
        }))

        for (const r of results) {
          state.tried++
          if (r.ok && stopOnHit) {
            state.hit = true
            state.hitIndex = r.globalIndex
            state.hitSeed = r.candidate.seed
            state.hitToken = r.candidate.token
            state.hitMsg = r.msg
            stopped = true
          } else {
            state.failCount++
          }
        }
        state.progress = Math.round((state.tried / total) * 100)
        index += CONCURRENCY
      }
      // 命中提前停止时，进度直接拉满显示
      if (state.hit) state.progress = 100
    }
  }
}
</script>

<style scoped>
.root-div { height: 100%; }

.vuln-info {
  border-radius: 10px;
  margin: 10px 20px 20px;
}

.header-div {
  font-size: 24px;
  color: #409EFF;
  font-weight: bold;
  padding: 10px;
  border-bottom: 1px solid #ccc;
}

.body-div {
  padding: 10px;
  font-family: Arial, sans-serif;
  font-size: 14px;
}

.vuln-detail {
  background-color: #dce9f8;
  padding: 10px;
  line-height: 1.7;
}

.code-demo {
  margin: 20px;
  border-top: 1px solid #ccc;
  padding-top: 20px;
}

pre code { font-size: 12px; }

.el-row { margin-bottom: 20px; }
.el-row:last-child { margin-bottom: 0; }
.el-col { border-radius: 4px; }
.bg-purple { background: #d3dce6; }

.grid-content {
  border-radius: 4px;
  height: 100%;
  padding: 10px;
}

.grid-flex {
  display: flex;
  align-items: stretch;
}

.center-dialog {
  text-align: center;
  margin: 0 auto;
}

.step-block {
  border: 1px solid #ebeef5;
  border-radius: 6px;
  padding: 14px 18px;
  margin-top: 18px;
  text-align: left;
  background: #fafafa;
}

.step-title {
  font-size: 15px;
  font-weight: bold;
  color: #303133;
  margin-bottom: 8px;
}

.step-num {
  display: inline-block;
  width: 22px;
  height: 22px;
  border-radius: 50%;
  background: #409eff;
  color: #fff;
  text-align: center;
  line-height: 22px;
  font-size: 13px;
  margin-right: 8px;
}

.step-desc {
  font-size: 13px;
  color: #606266;
  line-height: 1.7;
  margin-bottom: 10px;
}

.info-box {
  margin-top: 10px;
  padding: 10px 12px;
  background: #f4f4f5;
  border: 1px solid #e9e9eb;
  border-radius: 4px;
  font-size: 13px;
  color: #606266;
  line-height: 1.8;
}

.sample-pre {
  margin: 6px 0 0;
  padding: 8px;
  background: #fff;
  border: 1px solid #e4e7ed;
  border-radius: 4px;
  font-family: Consolas, Monaco, monospace;
  font-size: 12px;
  color: #303133;
  white-space: pre-wrap;
  word-break: break-all;
}

.brute-stat {
  margin-top: 8px;
  font-size: 13px;
  color: #606266;
}

.result-box {
  padding: 12px 16px;
  border-radius: 4px;
  line-height: 1.7;
  font-size: 13px;
  text-align: left;
  word-break: break-all;
}

.result-success {
  background-color: #f0f9eb;
  color: #67c23a;
  border: 1px solid #c2e7b0;
}

.result-warning {
  background-color: #fdf6ec;
  color: #e6a23c;
  border: 1px solid #f5dab1;
}
</style>
