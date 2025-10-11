<template>
  <div class="navbar">
    <hamburger :is-active="sidebar.opened" class="hamburger-container" @toggleClick="toggleSideBar" />

    <breadcrumb class="breadcrumb-container" />

    <div class="right-menu">
      <el-dropdown class="avatar-container" trigger="click">
        <div class="avatar-wrapper">
          <span class="user-name">{{ displayName }}</span>
          <span class="separator">|</span>
          <img :src="avatar + '?imageView2/1/w/80/h/80'" class="user-avatar">
          <i class="el-icon-caret-bottom" />
        </div>
        <el-dropdown-menu slot="dropdown" class="user-dropdown">
          <router-link to="/">
            <el-dropdown-item>
              Home
            </el-dropdown-item>
          </router-link>
          <a target="_blank" href="">
            <el-dropdown-item>Github</el-dropdown-item>
          </a>
          <el-dropdown-item @click.native="showUpdatePasswordDialog">
            <span style="display:block;">ResetPass</span>
          </el-dropdown-item>
          <el-dropdown-item divided @click.native="logout">
            <span style="display:block;">Log Out</span>
          </el-dropdown-item>
        </el-dropdown-menu>
      </el-dropdown>
    </div>

    <!-- 修改密码对话框 -->
    <el-dialog title="修改管理员密码" :visible.sync="updatePasswordDialogVisible" width="400px" class="center-dialog">
      <el-form :model="passwordForm" :rules="passwordRules" ref="passwordForm" label-width="100px">
        <el-form-item label="新密码" prop="newPassword">
          <el-input v-model="passwordForm.newPassword" type="password" placeholder="请输入新密码"></el-input>
        </el-form-item>
        <el-form-item label="确认新密码" prop="confirmPassword">
          <el-input v-model="passwordForm.confirmPassword" type="password" placeholder="请再次输入新密码"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="submitPasswordChange">提交</el-button>
          <el-button @click="cancelPasswordChange">取消</el-button>
        </el-form-item>
      </el-form>
      <div v-if="passwordChangeResult" style="margin-top: 15px;">
        <el-alert :title="passwordChangeResult" :type="passwordChangeResultType" show-icon></el-alert>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { mapGetters } from 'vuex'
import Breadcrumb from '@/components/Breadcrumb'
import Hamburger from '@/components/Hamburger'
import { changePassword } from '@/api/csrf'

export default {
  components: {
    Breadcrumb,
    Hamburger
  },
  data() {
    const validateConfirmPassword = (rule, value, callback) => {
      if (value === '') {
        callback(new Error('请再次输入新密码'))
      } else if (value !== this.passwordForm.newPassword) {
        callback(new Error('两次输入密码不一致!'))
      } else {
        callback()
      }
    }
    return {
      updatePasswordDialogVisible: false,
      passwordForm: {
        newPassword: '',
        confirmPassword: ''
      },
      passwordRules: {
        newPassword: [
          { required: true, message: '请输入新密码', trigger: 'blur' },
          { min: 6, message: '密码长度不能少于6位', trigger: 'blur' }
        ],
        confirmPassword: [
          { required: true, validator: validateConfirmPassword, trigger: 'blur' }
        ]
      },
      passwordChangeResult: '',
      passwordChangeResultType: 'success'
    }
  },
  computed: {
    ...mapGetters([
      'sidebar',
      'avatar',
      'username'
    ]),
    displayName() {
      return this.username || '未登录'
    }
  },
  methods: {
    toggleSideBar() {
      this.$store.dispatch('app/toggleSideBar')
    },
    async logout() {
      await this.$store.dispatch('user/logout')
      this.$router.push(`/login?redirect=${this.$route.fullPath}`)
    },
    showUpdatePasswordDialog() {
      this.updatePasswordDialogVisible = true
      this.passwordChangeResult = ''
      this.passwordForm = {
        newPassword: '',
        confirmPassword: ''
      }
    },
    submitPasswordChange() {
      this.$refs.passwordForm.validate((valid) => {
        if (valid) {
          const data = {
            newPassword: this.passwordForm.newPassword
          }
          changePassword(data)
            .then(response => {
              this.passwordChangeResult = '密码修改成功！请重新登录。'
              this.passwordChangeResultType = 'success'
              // 3秒后自动退出登录
              setTimeout(() => {
                this.updatePasswordDialogVisible = false
                this.logout()
              }, 3000)
            })
            .catch(error => {
              this.passwordChangeResult = '密码修改失败：' + (error.message || '未知错误')
              this.passwordChangeResultType = 'error'
            })
        } else {
          return false
        }
      })
    },
    cancelPasswordChange() {
      this.updatePasswordDialogVisible = false
      this.passwordForm = {
        newPassword: '',
        confirmPassword: ''
      }
      this.passwordChangeResult = ''
    }
  }
}
</script>

<style lang="scss" scoped>
.navbar {
  height: 50px;
  overflow: hidden;
  position: relative;
  background: #fff;
  box-shadow: 0 1px 4px rgba(0, 21, 41, .08);

  .hamburger-container {
    line-height: 46px;
    height: 100%;
    float: left;
    cursor: pointer;
    transition: background .3s;
    -webkit-tap-highlight-color: transparent;

    &:hover {
      background: rgba(0, 0, 0, .025)
    }
  }

  .breadcrumb-container {
    float: left;
  }

  .right-menu {
    float: right;
    height: 100%;
    line-height: 50px;

    &:focus {
      outline: none;
    }

    .right-menu-item {
      display: inline-block;
      padding: 0 8px;
      height: 100%;
      font-size: 18px;
      color: #5a5e66;
      vertical-align: text-bottom;

      &.hover-effect {
        cursor: pointer;
        transition: background .3s;

        &:hover {
          background: rgba(0, 0, 0, .025)
        }
      }
    }

    .avatar-container {
      margin-right: 30px;

      .avatar-wrapper {
        margin-top: 5px;
        position: relative;
        display: flex;
        align-items: center;

        .user-avatar {
          cursor: pointer;
          width: 40px;
          height: 40px;
          border-radius: 10px;
        }

        .user-name {
          margin: 0 5px;
          font-size: 14px;
          color: #606266;
        }

        .separator {
          margin: 0 5px;
          color: #909399;
        }

        .el-icon-caret-bottom {
          cursor: pointer;
          position: absolute;
          right: -20px;
          top: 25px;
          font-size: 12px;
        }
      }
    }
  }
}

.center-dialog {
  ::v-deep .el-dialog {
    margin-top: 10vh !important;
  }
  
  ::v-deep .el-dialog__body {
    padding: 20px 30px;
  }
  
  ::v-deep .el-form-item {
    margin-bottom: 20px;
  }
}
</style>
