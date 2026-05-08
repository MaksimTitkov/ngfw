<template>
  <div class="toast-stack">
    <div
      v-for="t in toastStore.toasts"
      :key="t.id"
      class="toast-msg"
      :class="t.type"
      @click="toastStore.remove(t.id)"
    >
      <i :class="iconClass(t.type)" />
      {{ t.message }}
    </div>
  </div>
</template>

<script setup>
import { useToastStore } from '@/stores/toast'

const toastStore = useToastStore()

function iconClass(type) {
  return {
    success: 'fas fa-check-circle',
    error: 'fas fa-exclamation-circle',
    warning: 'fas fa-exclamation-triangle',
    info: 'fas fa-info-circle',
  }[type] ?? 'fas fa-info-circle'
}
</script>
