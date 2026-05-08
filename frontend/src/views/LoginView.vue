<template>
  <div class="login-page">
    <div class="login-wrap">
      <div class="login-card">
        <div class="login-header">
          <div class="login-logo">
            <i class="fas fa-shield-halved" />
          </div>
          <h1 class="login-title">NGFW Manager</h1>
          <p class="login-sub">Policy Management System v2.0</p>
        </div>
        <div class="login-body">
          <!-- RO toggle -->
          <div class="mode-toggle">
            <button class="mode-btn" :class="{ active: !roMode }" @click="roMode = false" type="button">
              <i class="fas fa-unlock-keyhole" /> Full Access
            </button>
            <button class="mode-btn" :class="{ active: roMode }" @click="roMode = true" type="button">
              <i class="fas fa-eye" /> Read Only
            </button>
          </div>

          <form @submit.prevent="doLogin">
            <div class="field-mb">
              <label class="field-label">NGFW Host / URL</label>
              <div class="field-group">
                <div class="field-icon"><i class="fas fa-server" /></div>
                <input v-model="host" type="text" class="field-input" placeholder="192.168.1.1 or host:port" autocomplete="url" required />
              </div>
            </div>
            <div class="field-mb">
              <label class="field-label">Username</label>
              <div class="field-group">
                <div class="field-icon"><i class="fas fa-user" /></div>
                <input v-model="username" type="text" class="field-input" placeholder="admin" autocomplete="username" required autofocus />
              </div>
            </div>
            <div class="field-mb" style="margin-bottom:20px">
              <label class="field-label">Password</label>
              <div class="field-group">
                <div class="field-icon"><i class="fas fa-lock" /></div>
                <input v-model="password" type="password" class="field-input" placeholder="••••••••" autocomplete="current-password" required />
              </div>
            </div>

            <div v-if="error" class="error-box">
              <i class="fas fa-exclamation-circle" /> {{ error }}
            </div>

            <button type="submit" class="btn-login" :disabled="loading">
              <i :class="loading ? 'fas fa-spinner fa-spin' : 'fas fa-right-to-bracket'" />
              {{ loading ? 'Signing in…' : 'Sign In' }}
            </button>
          </form>
        </div>
      </div>
      <p class="footer-note">NGFW Policy Manager v2.0</p>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const auth = useAuthStore()

const roMode = ref(false)
const host = ref('')
const username = ref('')
const password = ref('')
const loading = ref(false)
const error = ref('')

async function doLogin() {
  loading.value = true
  error.value = ''
  try {
    await auth.login(username.value, password.value, host.value, roMode.value)
    router.push('/')
  } catch (e) {
    error.value = e.response?.data?.detail || 'Connection failed'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 60%, #0f172a 100%);
}
.login-wrap { width: 100%; max-width: 420px; padding: 16px; }
.login-card {
  background: #fff; border-radius: 16px;
  box-shadow: 0 24px 60px rgba(0,0,0,.4); overflow: hidden;
}
.login-header {
  background: linear-gradient(135deg, #1d4ed8, #3b82f6);
  padding: 28px 24px 22px; text-align: center; color: #fff;
}
.login-logo {
  width: 52px; height: 52px;
  background: rgba(255,255,255,.15); border-radius: 14px;
  display: flex; align-items: center; justify-content: center;
  margin: 0 auto 12px; font-size: 24px;
}
.login-title { font-size: 20px; font-weight: 800; margin: 0; }
.login-sub { font-size: 12px; opacity: .75; margin-top: 3px; margin-bottom: 0; }
.login-body { padding: 24px; }

/* Mode toggle */
.mode-toggle {
  display: flex; gap: 4px; margin-bottom: 20px;
  background: #f1f5f9; border-radius: 10px; padding: 4px;
}
.mode-btn {
  flex: 1; padding: 7px 10px; border: none; border-radius: 7px;
  background: transparent; color: #64748b;
  font-size: 12px; font-weight: 700; cursor: pointer; transition: all .15s;
  display: flex; align-items: center; justify-content: center; gap: 6px;
}
.mode-btn.active { background: #1d4ed8; color: #fff; box-shadow: 0 2px 8px rgba(29,78,216,.3); }
.mode-btn:not(.active):hover { color: #334155; }

.field-mb { margin-bottom: 14px; }
.field-label {
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .6px; color: #64748b; margin-bottom: 5px; display: block;
}
.field-group {
  display: flex; border: 1px solid #e2e8f0; border-radius: 8px;
  overflow: hidden; transition: border-color .15s, box-shadow .15s;
}
.field-group:focus-within {
  border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,.15);
}
.field-icon {
  width: 38px; display: flex; align-items: center; justify-content: center;
  background: #f8fafc; color: #94a3b8; font-size: 13px;
  border-right: 1px solid #e2e8f0; flex-shrink: 0;
}
.field-input {
  flex: 1; border: none; outline: none;
  padding: 9px 12px; font-size: 13px; background: transparent; color: #0f172a;
}
.btn-login {
  width: 100%; padding: 11px;
  background: linear-gradient(135deg, #1d4ed8, #3b82f6);
  color: #fff; border: none; border-radius: 8px;
  font-size: 14px; font-weight: 700; cursor: pointer; transition: opacity .15s;
  display: flex; align-items: center; justify-content: center; gap: 8px;
}
.btn-login:hover:not(:disabled) { opacity: .9; }
.btn-login:disabled { opacity: .6; cursor: not-allowed; }
.error-box {
  background: #fee2e2; color: #991b1b;
  border: 1px solid #fca5a5; border-radius: 8px;
  padding: 10px 14px; font-size: 13px; margin-bottom: 16px;
  display: flex; align-items: center; gap: 8px;
}
.footer-note {
  text-align: center; color: rgba(255,255,255,.3);
  font-size: 11px; margin-top: 16px;
}
</style>
