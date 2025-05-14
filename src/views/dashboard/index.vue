<template>
  <div class="poem-container">
    <p class="poem-title">破阵子·为陈同甫赋壮词以寄之</p>
    <p class="poem-author">宋·辛弃疾</p>
    <p class="poem-content" v-html="displayedText"></p>
  </div>
</template>

<script>
export default {
  data() {
    return {
      text: "醉里挑灯看剑，梦回吹角连营。八百里分麾下炙，五十弦翻塞外声，沙场秋点兵。马作的卢飞快，弓如霹雳弦惊。了却君王天下事，赢得生前身后名。可怜白发生！",
      displayedText: ""
    };
  },
  mounted() {
    this.displayText();
  },
  methods: {
    displayText() {
      let index = 0;
      let interval = setInterval(() => {
        if (this.text[index] === '。') {
          this.displayedText += this.text[index] + '<br>';
        } else {
          this.displayedText += this.text[index];
        }
        index++;
        if (index === this.text.length) {
          clearInterval(interval);
        }
      }, 100); // 每个字展示的间隔时间，单位为毫秒
    }
  }
};
</script>

<style>
.poem-container {
  /* 设置容器的宽度，可根据实际情况调整 */
  max-width: 800px;
  margin: 0 auto;
  padding: 20px;
  font-family: '宋体', serif;
  /* 或其他适合的字体 */
  /* text-align: center; */
  /* 居中对齐 */
}

.poem-title {
  font-size: 38px;
  font-weight: bold;
}

.poem-author {
  font-size: 18px;
  color: #666;
}

.poem-content {
  font-size: 24px;
  line-height: 2.5;
  /* text-indent: 2em; */
  /* 首行缩进 */
}
</style>