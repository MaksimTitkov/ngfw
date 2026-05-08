<template>
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;flex:1;min-width:120px;box-shadow:var(--shadow)">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
      <i :class="icon" :style="`color:${color};font-size:16px`" />
      <span style="font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px">{{ title }}</span>
    </div>
    <div :style="`font-size:28px;font-weight:800;color:${color}`">{{ value ?? 0 }}</div>
  </div>
</template>

<script setup>
defineProps({
  title: String,
  value: [Number, String],
  icon: String,
  color: { type: String, default: 'var(--accent)' },
})
</script>
