<template>
  <router-view />
  <AppToast />
</template>

<script setup>
import { watch } from 'vue'
import AppToast from '@/components/AppToast.vue'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()

watch(() => auth.isReadOnly, (ro) => {
  document.body.classList.toggle('ro-mode', ro)
}, { immediate: true })
</script>
