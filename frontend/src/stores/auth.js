import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import axios from 'axios'

export const useAuthStore = defineStore('auth', () => {
  const user = ref(null)
  const isAuthenticated = ref(false)
  const isReadOnly = computed(() => user.value?.role === 'ro')

  async function checkAuth() {
    try {
      const res = await axios.get('/api/v1/auth/me')
      user.value = res.data
      isAuthenticated.value = true
    } catch {
      isAuthenticated.value = false
      user.value = null
    }
  }

  async function login(username, password, host = '', ro = false) {
    const form = new FormData()
    form.append('username', username)
    form.append('password', password)
    form.append('host', host)
    form.append('ro', ro ? '1' : '0')
    await axios.post('/login', form)
    await checkAuth()
  }

  async function logout() {
    await axios.get('/logout')
    user.value = null
    isAuthenticated.value = false
  }

  return { user, isAuthenticated, isReadOnly, checkAuth, login, logout }
})
