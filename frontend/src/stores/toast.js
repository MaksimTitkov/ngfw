import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useToastStore = defineStore('toast', () => {
  const toasts = ref([])
  let nextId = 0

  function show(message, type = 'info', duration = 3500) {
    const id = ++nextId
    toasts.value.push({ id, message, type })
    setTimeout(() => remove(id), duration)
  }

  function remove(id) {
    toasts.value = toasts.value.filter((t) => t.id !== id)
  }

  const success = (msg) => show(msg, 'success')
  const error = (msg) => show(msg, 'error', 5000)
  const warning = (msg) => show(msg, 'warning')

  return { toasts, show, remove, success, error, warning }
})
