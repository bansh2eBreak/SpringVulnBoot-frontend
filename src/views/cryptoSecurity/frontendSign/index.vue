<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">前端加签被逆向（下单改价）</div>
      <div class="body-div">
        <el-tabs v-model="activeName" @tab-click="handleClick">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              <strong>前端加签</strong>是指前端用约定的密钥（secret）对请求参数计算一个签名（<code>sign</code>），和参数一起发给后端；后端用同一个 secret 重算签名并比对，<strong>对不上就拒绝</strong>，以此实现「<strong>防篡改</strong>」。
              <br /><br />
              <span style="color: red;">加签怎么工作？</span>
              <br />
              以电商下单为例，参数 <code>{ goodsId, price, count }</code>，前端这样算签名：
              <pre style="background:#f5f5f5;padding:10px;border-radius:4px;margin:8px 0;color:#333;">// 前端 JS（src/utils/frontendSign.js）
const SIGN_SECRET = "x9f2Kd8sLp3qW7mE";               // ❌ 密钥硬编码在前端
const raw  = "count=1&goodsId=2001&price=8999" + SIGN_SECRET;  // 参数按 key 升序拼接 + secret
const sign = md5(raw);                                 // 得到签名一起发给后端</pre>
              后端用<strong>同一个 secret</strong> 重算 <code>sign</code> 比对，看起来攻击者改了 <code>price</code> 就会验签失败——很完美？
              <br /><br />
              <span style="color: red;">致命缺陷：secret 藏在前端，等于没藏</span>
              <br />
              前端要算 <code>sign</code> 就<strong>必须持有 secret</strong>，而前端 JS 会完整下发到用户浏览器。攻击者只需：
              <br />
              ① F12 / 逆向打包后的 JS，搜索 <code>sign</code>、<code>md5</code> 关键字，拿到 <strong>secret</strong> 和<strong>拼接规则</strong>；
              <br />
              ② 自己把 <code>price</code> 改成 <code>1</code>，用同样的算法<strong>重新算出一个合法的 sign</strong>；
              <br />
              ③ 发出去，后端一验「我算的 sign == 你发的 sign」，<strong>放行</strong>——1 元买走 8999 的手机。
              <br /><br />
              <span style="color: #e6a23c; font-weight: bold;">⚠️ 一句话本质：</span>加签只能挡住「只会抓包改参数、不会逆向」的人；一旦 secret 被逆向，攻击者和正常前端<strong>完全平等</strong>，加签形同虚设。真正的防线必须在服务端。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              把安全校验寄托在「前端加签」上，一旦 secret 泄露，攻击者可<strong>批量、自动化</strong>地伪造合法请求：
              <br /><br />
              <span style="color: red;">主要危害：</span>
              <br />
              • <strong>下单改价 / 薅羊毛</strong>：篡改 <code>price</code>、<code>amount</code>、<code>discount</code> 等金额字段，低价甚至 0 元下单
              <br />
              • <strong>刷单 / 抢购作弊</strong>：脚本毫秒级构造大量合法请求，秒杀商品被机器抢空
              <br />
              • <strong>短信轰炸 / 接口滥用</strong>：逆向后批量调用发短信、发券等接口
              <br />
              • <strong>越权遍历</strong>：构造 <code>userId=1,2,3...</code> 的合法签名请求，批量拖库
              <br />
              • <strong>绕过 WAF</strong>：前端加密/加签后的流量 WAF 看不懂，注入 payload 反而「穿过」检测
              <br /><br />
              <span style="color: red;">真实场景：</span>
              <br />
              • 大量 App / 小程序把 <code>sign</code> 密钥写死在前端或客户端，被逆向后遭刷单、薅羊毛
              <br />
              • 电商抢购、优惠券、积分接口因「前端加签即安全」的误判被批量滥用
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <span style="color: red;">【必须】价格 / 金额以服务端为准</span>
              <br />
              下单金额<strong>永远由服务端用 <code>goodsId</code> 查数据库真实价格计算</strong>，绝不信任前端传来的 <code>price</code>。前端传 <code>price</code> 本身就是设计错误。
              <br /><br />
              <span style="color: red;">【必须】安全校验全部在服务端重做</span>
              <br />
              鉴权、归属校验（防越权/IDOR）、库存、限购、风控，必须在服务端完成，前端校验只用于「体验优化」。
              <br /><br />
              <span style="color: red;">【必须】不要把 secret 下发到客户端</span>
              <br />
              真正的签名/密钥只能留在服务端。要防重放用 <code>timestamp + nonce</code>（服务端记录 nonce 去重、窗口期外拒绝）；要防爬/限流用服务端风控（限频、人机验证、设备指纹）。
              <br /><br />
              <span style="color: red;">【正确认知】前端加签只是「减速带」</span>
              <br />
              它能提高自动化攻击的门槛（防君子不防小人），但<strong>不能替代任何服务端安全控制</strong>，更不能作为唯一信任依据。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://owasp.org/www-project-mobile-top-10/" target="_blank" style="text-decoration: underline;">《OWASP Mobile Top 10 - M8/M9 Reverse Engineering & Tampering》</a>：客户端逆向与篡改风险。<br />
              <a href="https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">《OWASP - 服务端应以权威数据为准》</a>：绝不信任客户端提交的敏感字段。<br />
              <a href="https://cwe.mitre.org/data/definitions/602.html" target="_blank" style="text-decoration: underline;">《CWE-602: Client-Side Enforcement of Server-Side Security》</a>：把服务端安全校验放到客户端执行。<br />
              <a href="https://cwe.mitre.org/data/definitions/807.html" target="_blank" style="text-decoration: underline;">《CWE-807: Reliance on Untrusted Inputs in a Security Decision》</a>：依赖不可信输入做安全决策。<br />
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
              漏洞代码 - 验签通过后信任前端 price
              <el-button type="danger" round size="mini" @click="showVulnDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * 前端加签 - 漏洞代码
 * 验签能挡住"只改包不会逆向"的人，但 secret 在前端可被逆向，
 * 一旦攻击者重算出合法 sign，后端就按前端传入的 price 计费。
 */
@PostMapping("/vuln/order")
public Result orderVuln(@RequestBody Map&lt;String, Object&gt; body) {
    long goodsId = toLong(body.get("goodsId"));
    long price   = toLong(body.get("price"));
    int  count   = (int) toLong(body.get("count"));
    String sign  = String.valueOf(body.get("sign"));

    // 1. 验签（能挡住只会改包的人）
    if (!verifySign(goodsId, price, count, sign)) {
        return Result.error("签名校验失败：参数被篡改或签名无效");
    }

    // 2. ❌ 漏洞点：验签通过后，无条件信任前端传来的 price
    long total = price * count;
    return Result.success(createOrder(goodsId, price, count, total));
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 - 忽略前端 price，按服务端真实价格计费
              <el-button type="success" round size="mini" @click="showSecDialog">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">
/**
 * 前端加签 - 安全代码
 * 核心：价格以服务端为准，绝不信任前端传来的 price。
 * 即使攻击者伪造出合法 sign，篡改 price 也无效。
 */
@PostMapping("/sec/order")
public Result orderSec(@RequestBody Map&lt;String, Object&gt; body) {
    long goodsId = toLong(body.get("goodsId"));
    long price   = toLong(body.get("price"));
    int  count   = (int) toLong(body.get("count"));
    String sign  = String.valueOf(body.get("sign"));

    if (!verifySign(goodsId, price, count, sign)) {
        return Result.error("签名校验失败：参数被篡改或签名无效");
    }

    // ✅ 安全点：忽略前端 price，用 goodsId 查服务端真实价格计费
    Goods goods = GOODS_CATALOG.get(goodsId);
    int  realPrice = goods.getPrice();
    long total     = (long) realPrice * count;
    return Result.success(createOrder(goodsId, realPrice, count, total));
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <!-- 漏洞版测试对话框 -->
    <el-dialog title="前端加签漏洞测试（下单改价）" :visible.sync="vulnDialogVisible" class="center-dialog" width="820px">
      <div style="text-align: left; color: red; font-style: italic;">
        跟着下面三步走，体会「签名能防改包，却防不住逆向」：先正常下单 → 再只改价不改签名（被拒）→ 最后逆向伪造签名改价（1 元下单成功）。
      </div>
      <br />

      <el-form class="demo-form-inline" label-width="80px">
        <el-form-item label="商品">
          <el-select v-model="vulnForm.goodsId" placeholder="选择商品" style="width: 100%;" @change="onVulnGoodsChange">
            <el-option v-for="g in goods" :key="g.id" :label="`${g.name}（真实价 ${g.price} 元）`" :value="g.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="数量">
          <el-input-number v-model="vulnForm.count" :min="1" :max="99" />
          <span style="margin-left: 12px; color: #909399;">真实单价：<b style="color:#f56c6c;">{{ currentRealPrice }}</b> 元</span>
        </el-form-item>
      </el-form>

      <!-- 步骤 1 -->
      <div class="step-block">
        <div class="step-title"><span class="step-num">1</span> 正常下单（前端按真实价加签）</div>
        <div class="step-desc">前端用真实单价 {{ currentRealPrice }} 元计算签名并下单，验签通过，正常成交。</div>
        <el-button type="primary" :loading="vulnForm.loading1" @click="step1NormalOrder">正常下单</el-button>
        <div v-if="vulnForm.result1" style="margin-top: 10px;">
          <div class="req-pre">请求体：{{ vulnForm.req1 }}</div>
          <div class="result-box" :class="vulnForm.result1.ok ? 'result-success' : 'result-error'">{{ vulnForm.result1.msg }}</div>
        </div>
      </div>

      <!-- 步骤 2 -->
      <div class="step-block">
        <div class="step-title"><span class="step-num">2</span> 只改价、不改签名（模拟只会抓包的人）</div>
        <div class="step-desc">把 price 改成 <b>1</b> 元，但<strong>沿用步骤 1 的旧签名</strong>直接发出 —— 后端验签失败，被拒绝。这说明签名<strong>确实能防篡改</strong>。</div>
        <el-button type="warning" :loading="vulnForm.loading2" @click="step2TamperNoResign">改价(不改签名)下单</el-button>
        <div v-if="vulnForm.result2" style="margin-top: 10px;">
          <div class="req-pre">请求体：{{ vulnForm.req2 }}</div>
          <div class="result-box" :class="vulnForm.result2.ok ? 'result-success' : 'result-error'">{{ vulnForm.result2.msg }}</div>
        </div>
      </div>

      <!-- 步骤 3 -->
      <div class="step-block">
        <div class="step-title"><span class="step-num">3</span> 逆向伪造签名改价（本漏洞核心）</div>
        <div class="step-desc">
          攻击者从 JS 里逆向出 <code>SIGN_SECRET = "{{ secret }}"</code> 和拼接规则，把 price 改成 <b>1</b> 元后<strong>重新算出一个合法 sign</strong> 再发 —— 后端验签通过，<strong>1 元下单成功</strong>。
        </div>
        <el-button type="danger" :loading="vulnForm.loading3" @click="step3ForgeResign">逆向伪造签名 → 1 元下单</el-button>
        <div v-if="vulnForm.result3" style="margin-top: 10px;">
          <div class="req-pre">请求体：{{ vulnForm.req3 }}</div>
          <div class="result-box" :class="vulnForm.result3.ok ? 'result-success' : 'result-error'">{{ vulnForm.result3.msg }}</div>
          <div v-if="vulnForm.result3.ok" class="result-box result-warning" style="margin-top: 8px;">
            🔑 注意看步骤 2 和步骤 3 的请求体：price 都是 1，但 <b>sign 不同</b>。步骤 3 用泄露的 secret 重算了合法签名，所以绕过成功。
          </div>
        </div>
      </div>
    </el-dialog>

    <!-- 安全版测试对话框 -->
    <el-dialog title="前端加签安全版测试（服务端查价）" :visible.sync="secDialogVisible" class="center-dialog" width="820px">
      <div style="text-align: left; color: green; font-style: italic;">
        用和漏洞版步骤 3 完全相同的「逆向伪造」手法攻击安全接口：即使签名合法，服务端也<strong>忽略前端价格，按真实价计费</strong>，篡改无效。
      </div>
      <br />

      <el-form class="demo-form-inline" label-width="80px">
        <el-form-item label="商品">
          <el-select v-model="secForm.goodsId" placeholder="选择商品" style="width: 100%;" @change="onSecGoodsChange">
            <el-option v-for="g in goods" :key="g.id" :label="`${g.name}（真实价 ${g.price} 元）`" :value="g.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="数量">
          <el-input-number v-model="secForm.count" :min="1" :max="99" />
          <span style="margin-left: 12px; color: #909399;">真实单价：<b style="color:#67c23a;">{{ currentSecRealPrice }}</b> 元</span>
        </el-form-item>
      </el-form>

      <div class="step-block">
        <div class="step-title"><span class="step-num">!</span> 逆向伪造签名改价，攻击安全接口</div>
        <div class="step-desc">把 price 改成 <b>1</b> 元并用泄露的 secret 重算出合法 sign，打到安全接口。</div>
        <el-button type="danger" :loading="secForm.loading" @click="secForgeAttack">逆向伪造签名 → 攻击安全接口</el-button>
        <div v-if="secForm.result" style="margin-top: 10px;">
          <div class="req-pre">请求体：{{ secForm.req }}</div>
          <div class="result-box" :class="secForm.result.ok ? 'result-success' : 'result-error'">{{ secForm.result.msg }}</div>
          <div v-if="secForm.result.ok" class="result-box result-success" style="margin-top: 8px;">
            ✅ 结论：验签只能证明「参数没被不懂逆向的人改过」，<strong>防篡改的真正防线是「价格以服务端为准」</strong>。
          </div>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { getGoods, createOrderVuln, createOrderSec } from '@/api/frontendSign'
import { SIGN_SECRET, buildSignedOrder } from '@/utils/frontendSign'

const TAMPERED_PRICE = 1

export default {
  name: 'FrontendSign',
  data() {
    return {
      activeName: 'first',
      vulnDialogVisible: false,
      secDialogVisible: false,
      secret: SIGN_SECRET,
      goods: [],
      vulnForm: this.initVulnForm(),
      secForm: this.initSecForm()
    }
  },
  computed: {
    currentRealPrice() {
      const g = this.goods.find(x => x.id === this.vulnForm.goodsId)
      return g ? g.price : 0
    },
    currentSecRealPrice() {
      const g = this.goods.find(x => x.id === this.secForm.goodsId)
      return g ? g.price : 0
    }
  },
  created() {
    this.loadGoods()
  },
  methods: {
    initVulnForm() {
      return {
        goodsId: 2001,
        count: 1,
        loading1: false,
        loading2: false,
        loading3: false,
        req1: '',
        req2: '',
        req3: '',
        result1: null,
        result2: null,
        result3: null,
        lastNormalSign: ''
      }
    },
    initSecForm() {
      return {
        goodsId: 2001,
        count: 1,
        loading: false,
        req: '',
        result: null
      }
    },
    handleClick() {},

    async loadGoods() {
      try {
        const res = await getGoods()
        this.goods = res.data || []
      } catch (e) {
        this.$message.error('加载商品失败：' + e.message)
      }
    },

    showVulnDialog() {
      this.vulnForm = this.initVulnForm()
      this.vulnDialogVisible = true
    },
    showSecDialog() {
      this.secForm = this.initSecForm()
      this.secDialogVisible = true
    },
    onVulnGoodsChange() {
      this.vulnForm.result1 = null
      this.vulnForm.result2 = null
      this.vulnForm.result3 = null
    },
    onSecGoodsChange() {
      this.secForm.result = null
    },

    // 步骤 1：正常下单（按真实价加签）
    async step1NormalOrder() {
      const price = this.currentRealPrice
      const payload = buildSignedOrder({ goodsId: this.vulnForm.goodsId, price, count: this.vulnForm.count })
      this.vulnForm.lastNormalSign = payload.sign
      this.vulnForm.req1 = JSON.stringify(payload)
      this.vulnForm.loading1 = true
      try {
        const res = await createOrderVuln(payload)
        this.vulnForm.result1 = { ok: true, msg: res.data.message }
      } catch (e) {
        this.vulnForm.result1 = { ok: false, msg: '下单失败：' + e.message }
      } finally {
        this.vulnForm.loading1 = false
      }
    },

    // 步骤 2：只改价、不改签名（沿用步骤 1 的旧签名）
    async step2TamperNoResign() {
      if (!this.vulnForm.lastNormalSign) {
        this.$message.warning('请先执行步骤 1 正常下单')
        return
      }
      // price 改成 1，但 sign 仍用步骤 1 为真实价算出的旧签名
      const payload = {
        goodsId: this.vulnForm.goodsId,
        price: TAMPERED_PRICE,
        count: this.vulnForm.count,
        sign: this.vulnForm.lastNormalSign
      }
      this.vulnForm.req2 = JSON.stringify(payload)
      this.vulnForm.loading2 = true
      try {
        const res = await createOrderVuln(payload)
        // 正常情况下不会走到这里（验签应失败）
        this.vulnForm.result2 = { ok: true, msg: res.data.message }
      } catch (e) {
        this.vulnForm.result2 = { ok: false, msg: '✅ 符合预期，被拒绝：' + e.message }
      } finally {
        this.vulnForm.loading2 = false
      }
    },

    // 步骤 3：逆向伪造签名改价（用泄露的 secret 对 price=1 重算 sign）
    async step3ForgeResign() {
      const payload = buildSignedOrder({ goodsId: this.vulnForm.goodsId, price: TAMPERED_PRICE, count: this.vulnForm.count })
      this.vulnForm.req3 = JSON.stringify(payload)
      this.vulnForm.loading3 = true
      try {
        const res = await createOrderVuln(payload)
        this.vulnForm.result3 = { ok: true, msg: res.data.message }
      } catch (e) {
        this.vulnForm.result3 = { ok: false, msg: '下单失败：' + e.message }
      } finally {
        this.vulnForm.loading3 = false
      }
    },

    // 安全版：同样逆向伪造签名改价，攻击安全接口
    async secForgeAttack() {
      const payload = buildSignedOrder({ goodsId: this.secForm.goodsId, price: TAMPERED_PRICE, count: this.secForm.count })
      this.secForm.req = JSON.stringify(payload)
      this.secForm.loading = true
      try {
        const res = await createOrderSec(payload)
        this.secForm.result = { ok: true, msg: res.data.message }
      } catch (e) {
        this.secForm.result = { ok: false, msg: '请求失败：' + e.message }
      } finally {
        this.secForm.loading = false
      }
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

.demo-form-inline { text-align: left; }

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

.req-pre {
  margin: 0 0 8px;
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

.result-error {
  background-color: #fef0f0;
  color: #f56c6c;
  border: 1px solid #fbc4c4;
}

.result-warning {
  background-color: #fdf6ec;
  color: #e6a23c;
  border: 1px solid #f5dab1;
}
</style>
