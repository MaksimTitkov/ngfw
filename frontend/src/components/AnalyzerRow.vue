<template>
  <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:#1e293b;border:1px solid rgba(255,255,255,.07);border-radius:8px">
    <span style="color:#94a3b8;font-size:12px">
      <i :class="`fas ${icon}`" :style="`color:${color};margin-right:7px`" />{{ label }}
    </span>
    <span :style="`background:rgba(${rgb},.15);color:${color};font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px`">{{ count }}</span>
  </div>
</template>

<script setup>
import { computed } from 'vue'
const props = defineProps({ icon: String, color: String, label: String, count: Number })
const rgb = computed(() => {
  const m = { '#f59e0b': '245,158,11', '#ef4444': '239,68,68', '#8b5cf6': '139,92,246', '#64748b': '100,116,139' }
  return m[props.color] || '100,116,139'
})
</script>
