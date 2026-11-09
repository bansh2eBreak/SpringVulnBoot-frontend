<template>
  <div class="root-div">
    <div class="vuln-info">
      <div class="header-div">业务逻辑漏洞 -- 优惠券并发超用</div>
      <div class="body-div">
        <el-tabs v-model="activeName">
          <el-tab-pane label="漏洞描述" name="first">
            <div class="vuln-detail">
              “每人限领一张”是一条典型的<strong>业务规则</strong>：同一账户在同一个活动中，最多只能拥有一条有效领取记录。很多系统会先查询“是否已领取”，确认没有后再插入领券记录；顺序请求下完全正常，但高并发时会产生竞态条件（Race Condition）。<br><br>
              <span style="color: red;">看起来正常的代码如何被绕过？</span><br>
              以本课的 <code>NEWUSER-10</code> 活动为例，数据库初始没有当前管理员的领券记录。两个请求几乎同时到达时：
              <pre style="background:#f5f5f5;padding:10px;border-radius:4px;margin:8px 0;color:#333;">请求 A：SELECT COUNT(*) ... → 0，判断“可以领取”
请求 B：SELECT COUNT(*) ... → 0，判断“可以领取”
请求 A：INSERT 领取记录 → 成功
请求 B：INSERT 领取记录 → 仍然成功</pre>
              最终同一 <code>admin_id + campaign_code</code> 出现多条记录。<strong>单个事务内部没有出错</strong>，问题是两个事务在“检查 → 写入”之间相互穿插。<br><br>
              <span style="color: red;">致命缺陷：业务规则只存在于应用层</span><br>
              普通索引只能让查询更快，不能保证数据唯一；<code>@Transactional</code> 只能保证一个请求内的操作一起成功或回滚，不能自动把两条 SQL 变为不可分割的原子操作。<span style="color: red;">若数据库没有联合唯一约束，最终就允许不符合业务规则的重复数据落库。</span><br><br>
              <span style="color: #e6a23c; font-weight: bold;">⚠️ 一句话本质：</span>先判断“能不能领”，再执行“领取”属于 TOCTOU（检查时与使用时不一致）问题；“每人限领一次”必须由数据库或原子操作最终保证。
            </div>
          </el-tab-pane>
          <el-tab-pane label="漏洞危害" name="second">
            <div class="vuln-detail">
              攻击者不需要伪造身份，也不需要修改券码；只要持有自己的合法登录态，就可并发重放“领取优惠券”请求，突破次数限制。单次点击和常规功能测试通常看不出问题，因此这类漏洞常在营销活动上线后才暴露。<br><br>
              <span style="color: red;">主要危害：</span><br>
              • <strong>优惠券超发 / 薅羊毛</strong>：同一账户重复领取满减券、兑换券、会员权益券，再批量使用或转卖；<br>
              • <strong>营销预算失控</strong>：本应发放 1 张的高面额券被领取多次，补贴成本被放大；<br>
              • <strong>活动资源耗尽</strong>：若同时存在总库存扣减，竞态还可能导致库存超卖、负库存或有效券多于活动库存；<br>
              • <strong>数据与财务不一致</strong>：业务页面显示“每人限领 1 张”，数据库却保存多张有效券，后续核销、退款和风控难以对账；<br>
              • <strong>自动化攻击成本低</strong>：Burp Suite、脚本或多个并发连接即可触发，不需要复杂漏洞利用链。<br><br>
              <span style="color: red;">常见同类场景：</span><br>
              • 秒杀商品的库存扣减；• 积分兑换；• 抽奖次数领取；• 邀请奖励；• 余额提现；• 支付回调重复处理。<br>
              它们的共同点都是：<strong>有次数、库存或金额上限，却把检查和状态变更拆成了可并发的多个步骤。</strong>
            </div>
          </el-tab-pane>
          <el-tab-pane label="安全编码" name="third">
            <div class="vuln-detail">
              <span style="color: red;">【必须】将“每人限领一次”声明为数据库约束</span><br>
              对 <code>admin_id + campaign_code</code> 建立联合唯一索引。无论应用层有多少并发请求，数据库物理上最多只允许一条记录存在：
              <pre style="background:#f5f5f5;padding:10px;border-radius:4px;margin:8px 0;color:#333;">UNIQUE KEY uk_admin_campaign (admin_id, campaign_code)</pre>
              普通索引用于提升查询性能；<strong>唯一索引 / 唯一约束</strong>才是保证“不重复”的最终防线。<br><br>
              <span style="color: red;">【必须】把重复键冲突转为正常业务结果</span><br>
              直接尝试插入记录，成功即领取成功；发生 <code>DuplicateKeyException</code> 时返回“每人限领一张”。不要先查询后把“没有记录”当成安全结论。<br><br>
              <span style="color: red;">【必须】按资源类型选择原子控制方式</span><br>
              本课的“每人一张”适合联合唯一约束；总库存适合 <code>UPDATE ... SET stock = stock - 1 WHERE stock &gt; 0</code> 并检查影响行数；余额、订单、支付等多步骤写入需要事务、幂等键和必要的行锁。<br><br>
              <span style="color: red;">【正确认知】事务不是并发安全的同义词</span><br>
              <code>@Transactional</code> 解决的是单个事务的原子性与回滚，不会自动串行化全部请求。只有把业务不变量交给唯一约束、条件更新、锁或幂等机制，才能真正抵抗并发。
            </div>
          </el-tab-pane>
          <el-tab-pane label="参考文章" name="fourth">
            <div class="vuln-detail">
              <a href="https://portswigger.net/web-security/race-conditions" target="_blank" style="text-decoration: underline;">《PortSwigger - Race conditions》</a>：Web 业务竞态条件的原理与并发测试方法。<br>
              <a href="https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun" target="_blank" style="text-decoration: underline;">《PortSwigger - Limit overrun race conditions》</a>：突破次数限制的竞态实验。<br>
              <a href="https://dev.mysql.com/doc/refman/8.0/en/create-index.html" target="_blank" style="text-decoration: underline;">《MySQL CREATE INDEX》</a>：MySQL 普通索引与唯一索引的语义。<br>
              <a href="https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html" target="_blank" style="text-decoration: underline;">《OWASP Transaction Authorization Cheat Sheet》</a>：事务和业务授权设计建议。
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
              正常领取流程（顺序请求）
              <el-button type="primary" round size="mini" @click="normalVisible = true">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * 同一账户顺序调用两次时：
 * 第一次插入记录；第二次查询能读到记录并被拒绝。
 */
@Transactional
public ClaimResult claim(Integer adminId, String campaignCode) {
    int count = claimMapper.countByAdminAndCampaign(
        adminId, campaignCode);
    if (count &gt; 0) {
        return ClaimResult.fail("每人限领一张");
    }

    claimMapper.insert(adminId, campaignCode, COUPON_NAME);
    return ClaimResult.ok("领取成功");
}</code></pre>
          </div>
        </el-col>
      </el-row>
      <el-row :gutter="20" class="grid-flex">
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              漏洞代码 — 先查询后插入
              <el-button type="danger" round size="mini" @click="vulnVisible = true">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * 漏洞：检查与插入分成两条 SQL。
 * 即使 @Transactional，两个事务仍可同时读到 count = 0。
 */
@Transactional
public ClaimResult claimVuln(Integer adminId, String campaignCode) {
    int count = vulnMapper.countByAdminAndCampaign(
        adminId, campaignCode);
    if (count &gt; 0) {
        return ClaimResult.fail("每人限领一张");
    }

    // ❌ 表中只有普通索引，没有 UNIQUE(admin_id, campaign_code)
    vulnMapper.insert(adminId, campaignCode, COUPON_NAME);
    return ClaimResult.ok("领取成功");
}</code></pre>
          </div>
        </el-col>
        <el-col :span="12">
          <div class="grid-content bg-purple">
            <el-row type="flex" justify="space-between" align="middle">
              安全代码 — 数据库唯一约束
              <el-button type="success" round size="mini" @click="secVisible = true">去测试</el-button>
            </el-row>
            <pre v-highlightjs><code class="java">/**
 * 表结构：UNIQUE KEY uk_admin_campaign(admin_id, campaign_code)
 * 数据库保证同一活动的领取记录最多一条。
 */
@Transactional
public ClaimResult claimSecure(Integer adminId, String campaignCode) {
    try {
        secMapper.insert(adminId, campaignCode, COUPON_NAME);
        return ClaimResult.ok("领取成功");
    } catch (DuplicateKeyException e) {
        // ✅ 并发请求中，只有一个插入成功
        return ClaimResult.fail("每人限领一张");
    }
}</code></pre>
          </div>
        </el-col>
      </el-row>
    </div>

    <el-dialog :visible.sync="normalVisible" width="800px" :show-close="true" :close-on-click-modal="true">
      <div slot="title" style="text-align: center; font-size: 18px;">正常领取流程（顺序请求）</div>
      <div class="test-container">
        <div class="test-section">
          <h3>1. 活动说明</h3>
          <el-alert title="当前靶场管理员就是本次测试账户" type="info" :closable="false" show-icon>
            <div style="text-align: left; line-height: 1.8;">
              <p><strong>活动券：</strong>NEWUSER-10（新人满 100 减 10 元券）</p>
              <p><strong>领取规则：</strong>每人限领 1 张</p>
              <p><strong>认证方式：</strong>复用当前靶场管理员的 Authorization JWT，不需要额外登录。</p>
            </div>
          </el-alert>
        </div>
        <div class="test-section">
          <h3>2. 重置并顺序领取</h3>
          <p class="section-tip">先重置当前测试账户的记录，再依次点击两次领取。顺序请求下，第二次能够正确识别已有记录。</p>
          <div class="test-buttons">
            <el-button type="warning" :loading="resetting" @click="resetAll">重置测试数据</el-button>
            <el-button type="primary" :loading="normalClaiming" @click="claimNormal">领取一次</el-button>
            <el-button @click="loadStatus('normal')">查询领取记录</el-button>
          </div>
          <div v-if="normalResult" class="result-box">
            <el-alert :title="normalResult.claimed ? '领取成功' : '领取被拒绝'" :description="normalResult.message" :type="normalResult.claimed ? 'success' : 'warning'" :closable="false" show-icon />
          </div>
          <div class="claim-list">
            <p>当前领取记录：{{ normalStatus.claimCount }} 条</p>
            <el-table v-if="normalStatus.claims.length" :data="normalStatus.claims" size="mini" border>
              <el-table-column prop="id" label="记录 ID" width="90" />
              <el-table-column prop="campaignCode" label="活动券码" width="150" />
              <el-table-column prop="couponName" label="优惠券名称" />
              <el-table-column prop="status" label="状态" width="100" />
              <el-table-column prop="claimedAt" label="领取时间" width="180" />
            </el-table>
          </div>
        </div>
      </div>
    </el-dialog>

    <el-dialog :visible.sync="vulnVisible" width="800px" :show-close="true" :close-on-click-modal="true">
      <div slot="title" style="text-align: center; font-size: 18px;">优惠券并发超用测试</div>
      <div class="test-container">
        <div class="test-section">
          <h3>攻击步骤说明</h3>
          <el-alert title="不在服务端人为增加延时，请使用真实并发请求触发竞态" type="warning" :closable="false" show-icon>
            <div style="text-align: left; line-height: 1.8;">
              <p><strong>第 1 步：</strong>重置当前测试账户的漏洞版领取记录。</p>
              <p><strong>第 2 步：</strong>点击一次“单次领取请求”，在 Burp 中截获请求。</p>
              <p><strong>第 3 步：</strong>将相同请求发送到 Repeater 或 Turbo Intruder，并发重放多次。</p>
              <p><strong>第 4 步：</strong>回到此处查询记录。出现两条及以上记录即复现成功。</p>
            </div>
          </el-alert>
        </div>
        <div class="test-section">
          <h3>1. 准备请求</h3>
          <div class="test-buttons">
            <el-button type="warning" :loading="resetting" @click="resetAll">重置测试数据</el-button>
            <el-button type="danger" :loading="vulnClaiming" @click="claimVuln">单次领取请求</el-button>
          </div>
          <div v-if="vulnResult" class="result-box">
            <el-alert :title="vulnResult.claimed ? '本次请求领取成功' : '本次请求被拒绝'" :description="vulnResult.message" :type="vulnResult.claimed ? 'success' : 'warning'" :closable="false" show-icon />
          </div>
          <div class="request-example">{{ vulnRequest }}</div>
        </div>
        <div class="test-section">
          <h3>2. 浏览器并发复现</h3>
          <p class="section-tip">浏览器会同时发送多次真实的领取请求，不修改服务端代码、不增加人为延时。若本轮未触发竞态，可重置后提高请求数重试。</p>
          <el-form inline class="concurrent-form">
            <el-form-item label="并发请求数">
              <el-input-number v-model="concurrentCount" :min="2" :max="100" :disabled="vulnConcurrentLoading" />
            </el-form-item>
            <el-form-item>
              <el-button type="danger" :loading="vulnConcurrentLoading" @click="runConcurrent('vuln')">浏览器并发领取</el-button>
            </el-form-item>
          </el-form>
          <div v-if="vulnConcurrentResult" class="result-box">
            <el-alert
              :title="vulnConcurrentResult.claimCount > 1 ? '漏洞复现成功' : '本轮未触发竞态'"
              :description="concurrentDescription(vulnConcurrentResult, 'vuln')"
              :type="vulnConcurrentResult.claimCount > 1 ? 'error' : 'warning'"
              :closable="false"
              show-icon
            />
          </div>
        </div>
        <div class="test-section">
          <h3>3. 查询验证结果</h3>
          <div class="test-buttons">
            <el-button type="danger" :loading="vulnLoading" @click="loadStatus('vuln')">查询我的领券记录</el-button>
          </div>
          <div v-if="vulnStatus.claimCount > 1" class="result-box">
            <el-alert title="漏洞复现成功" :description="'当前测试账户领取了 ' + vulnStatus.claimCount + ' 张 NEWUSER-10，但业务规则只允许 1 张。'" type="error" :closable="false" show-icon />
          </div>
          <div class="claim-list">
            <p>当前领取记录：{{ vulnStatus.claimCount }} 条</p>
            <el-table v-if="vulnStatus.claims.length" :data="vulnStatus.claims" size="mini" border>
              <el-table-column prop="id" label="记录 ID" width="90" />
              <el-table-column prop="campaignCode" label="活动券码" width="150" />
              <el-table-column prop="couponName" label="优惠券名称" />
              <el-table-column prop="status" label="状态" width="100" />
              <el-table-column prop="claimedAt" label="领取时间" width="180" />
            </el-table>
          </div>
        </div>
      </div>
    </el-dialog>

    <el-dialog :visible.sync="secVisible" width="800px" :show-close="true" :close-on-click-modal="true">
      <div slot="title" style="text-align: center; font-size: 18px;">安全代码测试 — 每人限领一次</div>
      <div class="test-container">
        <div class="test-section">
          <h3>1. 安全控制点</h3>
          <el-alert title="数据库的联合唯一约束是最终防线" type="success" :closable="false" show-icon>
            <div style="text-align: left; line-height: 1.8;">
              <p>安全表设置 <code>UNIQUE(admin_id, campaign_code)</code>。</p>
              <p>无论同时发送多少个相同请求，数据库最多只能插入一条领取记录。</p>
            </div>
          </el-alert>
        </div>
        <div class="test-section">
          <h3>2. 浏览器并发测试</h3>
          <p class="section-tip">重置后直接发起浏览器并发请求。无论同时发送多少次，安全表的联合唯一约束都只允许一条记录插入成功。</p>
          <div class="test-buttons">
            <el-button type="warning" :loading="resetting" @click="resetAll">重置测试数据</el-button>
            <el-button type="success" :loading="secClaiming" @click="claimSec">单次领取请求</el-button>
          </div>
          <div v-if="secResult" class="result-box">
            <el-alert :title="secResult.claimed ? '本次请求领取成功' : '本次请求被拒绝'" :description="secResult.message" :type="secResult.claimed ? 'success' : 'warning'" :closable="false" show-icon />
          </div>
          <div class="request-example">{{ secRequest }}</div>
          <el-form inline class="concurrent-form">
            <el-form-item label="并发请求数">
              <el-input-number v-model="concurrentCount" :min="2" :max="100" :disabled="secConcurrentLoading" />
            </el-form-item>
            <el-form-item>
              <el-button type="success" :loading="secConcurrentLoading" @click="runConcurrent('sec')">浏览器并发领取</el-button>
            </el-form-item>
          </el-form>
          <div v-if="secConcurrentResult" class="result-box">
            <el-alert
              :title="secConcurrentResult.claimCount === 1 ? '安全校验通过' : '安全校验异常'"
              :description="concurrentDescription(secConcurrentResult, 'sec')"
              :type="secConcurrentResult.claimCount === 1 ? 'success' : 'error'"
              :closable="false"
              show-icon
            />
          </div>
        </div>
        <div class="test-section">
          <h3>3. 查询验证结果</h3>
          <div class="test-buttons">
            <el-button type="success" :loading="secLoading" @click="loadStatus('sec')">查询我的领券记录</el-button>
          </div>
          <div v-if="secStatus.claimCount === 1" class="result-box">
            <el-alert title="安全校验通过" description="当前测试账户只有 1 条领取记录，其余并发请求会被数据库唯一约束拒绝。" type="success" :closable="false" show-icon />
          </div>
          <div class="claim-list">
            <p>当前领取记录：{{ secStatus.claimCount }} 条</p>
            <el-table v-if="secStatus.claims.length" :data="secStatus.claims" size="mini" border>
              <el-table-column prop="id" label="记录 ID" width="90" />
              <el-table-column prop="campaignCode" label="活动券码" width="150" />
              <el-table-column prop="couponName" label="优惠券名称" />
              <el-table-column prop="status" label="状态" width="100" />
              <el-table-column prop="claimedAt" label="领取时间" width="180" />
            </el-table>
          </div>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import {
  claimCouponNormal,
  claimCouponSec,
  claimCouponVuln,
  couponStatusNormal,
  couponStatusSec,
  couponStatusVuln,
  resetCouponRace
} from '@/api/couponRace'

const emptyStatus = () => ({
  claimCount: 0,
  claims: []
})

export default {
  name: 'CouponRace',
  data() {
    return {
      activeName: 'first',
      normalVisible: false,
      vulnVisible: false,
      secVisible: false,
      resetting: false,
      normalClaiming: false,
      vulnClaiming: false,
      secClaiming: false,
      vulnConcurrentLoading: false,
      secConcurrentLoading: false,
      vulnLoading: false,
      secLoading: false,
      normalResult: null,
      vulnResult: null,
      secResult: null,
      normalStatus: emptyStatus(),
      vulnStatus: emptyStatus(),
      secStatus: emptyStatus(),
      concurrentCount: 50,
      vulnConcurrentResult: null,
      secConcurrentResult: null,
      vulnRequest: 'POST /businessLogic/couponRace/vuln/claim\nAuthorization: <当前靶场管理员 JWT>\nContent-Type: application/json\n\n{"campaignCode":"NEWUSER-10"}',
      secRequest: 'POST /businessLogic/couponRace/sec/claim\nAuthorization: <当前靶场管理员 JWT>\nContent-Type: application/json\n\n{"campaignCode":"NEWUSER-10"}'
    }
  },
  methods: {
    async resetAll() {
      this.resetting = true
      try {
        await resetCouponRace()
        this.normalResult = null
        this.vulnResult = null
        this.secResult = null
        this.vulnConcurrentResult = null
        this.secConcurrentResult = null
        await Promise.all([this.loadStatus('normal'), this.loadStatus('vuln'), this.loadStatus('sec')])
      } finally {
        this.resetting = false
      }
    },
    async claimNormal() {
      this.normalClaiming = true
      try {
        const res = await claimCouponNormal()
        this.normalResult = res.data
        await this.loadStatus('normal')
      } finally {
        this.normalClaiming = false
      }
    },
    async claimVuln() {
      this.vulnClaiming = true
      try {
        const res = await claimCouponVuln()
        this.vulnResult = res.data
        await this.loadStatus('vuln')
      } finally {
        this.vulnClaiming = false
      }
    },
    async claimSec() {
      this.secClaiming = true
      try {
        const res = await claimCouponSec()
        this.secResult = res.data
        await this.loadStatus('sec')
      } finally {
        this.secClaiming = false
      }
    },
    async runConcurrent(mode) {
      const count = this.concurrentCount
      const claim = mode === 'vuln' ? claimCouponVuln : claimCouponSec
      const loadingKey = mode + 'ConcurrentLoading'
      this[loadingKey] = true
      this[mode + 'ConcurrentResult'] = null
      try {
        const results = await Promise.allSettled(
          Array.from({ length: count }, () => claim())
        )
        let succeeded = 0
        let rejected = 0
        let failed = 0
        results.forEach(result => {
          if (result.status !== 'fulfilled') {
            failed += 1
          } else if (result.value.data.claimed) {
            succeeded += 1
          } else {
            rejected += 1
          }
        })
        await this.loadStatus(mode)
        this[mode + 'ConcurrentResult'] = {
          requested: count,
          succeeded,
          rejected,
          failed,
          claimCount: this[mode + 'Status'].claimCount
        }
      } finally {
        this[loadingKey] = false
      }
    },
    concurrentDescription(result, mode) {
      const summary = '本轮并发请求：' + result.requested +
        '；领取成功响应：' + result.succeeded +
        '；已领取拒绝：' + result.rejected +
        '；请求异常：' + result.failed +
        '；数据库实际领取记录：' + result.claimCount + ' 条。'
      if (mode === 'vuln' && result.claimCount <= 1) {
        return summary + ' 浏览器存在单域并发限制，可重置后提高请求数重试，或使用 Burp Suite / 测试脚本。'
      }
      return summary
    },
    async loadStatus(type) {
      if (type === 'vuln') {
        this.vulnLoading = true
      } else if (type === 'sec') {
        this.secLoading = true
      }
      try {
        let res
        if (type === 'normal') {
          res = await couponStatusNormal()
        } else if (type === 'vuln') {
          res = await couponStatusVuln()
        } else {
          res = await couponStatusSec()
        }
        this[type + 'Status'] = res.data
      } finally {
        if (type === 'vuln') {
          this.vulnLoading = false
        } else if (type === 'sec') {
          this.secLoading = false
        }
      }
    }
  }
}
</script>

<style scoped>
.vuln-info { border-radius: 10px; margin: 10px 20px 20px; }
.header-div { font-size: 24px; color: #409EFF; font-weight: bold; padding: 10px; border-bottom: 1px solid #ccc; }
.body-div { padding: 10px; font-size: 14px; }
.vuln-detail { background-color: #dce9f8; padding: 10px; }
.code-demo { margin: 20px; border-top: 1px solid #ccc; padding-top: 20px; }
pre code { font-size: 12px; }
.el-row { margin-bottom: 20px; }
.el-col { border-radius: 4px; }
.bg-purple { background: #d3dce6; }
.grid-content { border-radius: 4px; height: 100%; padding: 10px; }
.grid-flex { display: flex; align-items: stretch; }
.test-container { padding: 20px; }
.test-section { margin-bottom: 30px; padding: 20px; border: 1px solid #e4e7ed; border-radius: 8px; background-color: #fafafa; }
.test-section h3 { margin-top: 0; margin-bottom: 15px; color: #409EFF; font-size: 16px; }
.section-tip { margin: 0 0 12px; font-size: 13px; color: #606266; line-height: 1.7; }
.test-buttons { margin-bottom: 15px; }
.test-buttons .el-button { margin-right: 10px; }
.result-box { margin-top: 15px; }
.request-example { margin-top: 15px; padding: 12px; background: #282c34; color: #d7dae0; border-radius: 4px; font: 12px/1.6 Consolas, monospace; white-space: pre-wrap; }
.concurrent-form { margin-top: 15px; }
.claim-list { margin-top: 15px; }
.claim-list p { margin: 0 0 8px; font-size: 13px; color: #606266; }
</style>
