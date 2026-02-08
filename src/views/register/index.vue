<template>
  <div class="login-container">
    <el-form ref="registerForm" :model="registerForm" :rules="registerRules" class="login-form" auto-complete="on"
      label-position="left">

      <div class="title-container">
        <h3 class="title">用户注册</h3>
      </div>

      <el-form-item prop="username">
        <span class="svg-container">
          <svg-icon icon-class="user" />
        </span>
        <el-input ref="username" v-model="registerForm.username" placeholder="用户名" name="username" type="text"
          tabindex="1" auto-complete="on" />
      </el-form-item>

      <el-form-item prop="password">
        <span class="svg-container">
          <svg-icon icon-class="password" />
        </span>
        <el-input :key="passwordType" ref="password" v-model="registerForm.password" :type="passwordType"
          placeholder="密码（至少6位）" name="password" tabindex="2" auto-complete="on" />
        <span class="show-pwd" @click="showPwd">
          <svg-icon :icon-class="passwordType === 'password' ? 'eye' : 'eye-open'" />
        </span>
      </el-form-item>

      <el-form-item prop="confirmPassword">
        <span class="svg-container">
          <svg-icon icon-class="password" />
        </span>
        <el-input :key="confirmPasswordType" ref="confirmPassword" v-model="registerForm.confirmPassword" 
          :type="confirmPasswordType" placeholder="确认密码" name="confirmPassword" tabindex="3" 
          auto-complete="on" @keyup.enter.native="handleRegister" />
        <span class="show-pwd" @click="showConfirmPwd">
          <svg-icon :icon-class="confirmPasswordType === 'password' ? 'eye' : 'eye-open'" />
        </span>
      </el-form-item>

      <el-button :loading="loading" type="primary" style="width:100%;margin-bottom:10px;"
        @click.native.prevent="handleRegister">注册</el-button>

      <div style="text-align: center; margin-bottom: 25px;">
        <span style="color: #909399; font-size: 14px;">已有账号？</span>
        <el-button type="text" @click="goToLogin" style="font-size: 14px; padding: 0; margin-left: 5px;">
          立即登录
        </el-button>
      </div>

    </el-form>
  </div>
</template>

<script>
import { validUsername } from '@/utils/validate'
import { register } from '@/api/user'

export default {
  name: 'Register',
  data() {
    const validateUsername = (rule, value, callback) => {
      if (!validUsername(value)) {
        callback(new Error('请输入用户名'))
      } else {
        callback()
      }
    }
    const validatePassword = (rule, value, callback) => {
      if (value.length < 6) {
        callback(new Error('密码长度不能少于6位'))
      } else {
        callback()
      }
    }
    const validateConfirmPassword = (rule, value, callback) => {
      if (value === '') {
        callback(new Error('请再次输入密码'))
      } else if (value !== this.registerForm.password) {
        callback(new Error('两次输入密码不一致'))
      } else {
        callback()
      }
    }
    return {
      registerForm: {
        username: '',
        password: '',
        confirmPassword: ''
      },
      registerRules: {
        username: [{ required: true, trigger: 'blur', validator: validateUsername }],
        password: [{ required: true, trigger: 'blur', validator: validatePassword }],
        confirmPassword: [{ required: true, trigger: 'blur', validator: validateConfirmPassword }]
      },
      loading: false,
      passwordType: 'password',
      confirmPasswordType: 'password'
    }
  },
  methods: {
    showPwd() {
      if (this.passwordType === 'password') {
        this.passwordType = ''
      } else {
        this.passwordType = 'password'
      }
      this.$nextTick(() => {
        this.$refs.password.focus()
      })
    },
    showConfirmPwd() {
      if (this.confirmPasswordType === 'password') {
        this.confirmPasswordType = ''
      } else {
        this.confirmPasswordType = 'password'
      }
      this.$nextTick(() => {
        this.$refs.confirmPassword.focus()
      })
    },
    handleRegister() {
      this.$refs.registerForm.validate(valid => {
        if (valid) {
          this.loading = true
          const data = {
            username: this.registerForm.username,
            password: this.registerForm.password
          }
          
          register(data).then(res => {
            if (res.code === 0) {
              this.$message.success('注册成功！即将跳转到登录页...')
              // 2秒后跳转到登录页
              setTimeout(() => {
                this.$router.push('/login')
              }, 2000)
            } else {
              this.$message.error(res.msg || '注册失败')
              this.loading = false
            }
          }).catch(error => {
            console.error('注册失败:', error)
            this.loading = false
          })
        } else {
          console.log('表单验证失败')
          return false
        }
      })
    },
    goToLogin() {
      this.$router.push('/login')
    }
  }
}
</script>

<style lang="scss" scoped>
/* 使用与登录页完全相同的样式 */
$bg:#283443;
$light_gray:#fff;
$cursor: #fff;

@supports (-webkit-mask: none) and (not (cater-color: $cursor)) {
  .login-container .el-input input {
    color: $cursor;
  }
}

/* reset element-ui css */
.login-container {
  .el-input {
    display: inline-block;
    height: 47px;
    width: 85%;

    input {
      background: transparent;
      border: 0px;
      appearance: none;
      -webkit-appearance: none;
      border-radius: 0px;
      padding: 12px 5px 12px 15px;
      color: $light_gray;
      height: 47px;
      caret-color: $cursor;

      &:-webkit-autofill {
        box-shadow: 0 0 0px 1000px $bg inset !important;
        -webkit-text-fill-color: $cursor !important;
      }
    }
  }

  .el-form-item {
    border: 1px solid rgba(255, 255, 255, 0.1);
    background: rgba(0, 0, 0, 0.1);
    border-radius: 5px;
    color: #454545;
  }
}

.login-container {
  min-height: 100%;
  width: 100%;
  background-color: $bg;
  overflow: hidden;

  .login-form {
    position: relative;
    width: 520px;
    max-width: 100%;
    padding: 160px 35px 0;
    margin: 0 auto;
    overflow: hidden;
  }

  .tips {
    font-size: 14px;
    color: #fff;
    margin-bottom: 10px;

    span {
      &:first-of-type {
        margin-right: 16px;
      }
    }
  }

  .svg-container {
    padding: 6px 5px 6px 15px;
    color: $light_gray;
    vertical-align: middle;
    width: 30px;
    display: inline-block;
  }

  .title-container {
    position: relative;

    .title {
      font-size: 26px;
      color: $light_gray;
      margin: 0px auto 40px auto;
      text-align: center;
      font-weight: bold;
    }
  }

  .show-pwd {
    position: absolute;
    right: 10px;
    top: 7px;
    font-size: 16px;
    color: $light_gray;
    cursor: pointer;
    user-select: none;
  }
}
</style>
