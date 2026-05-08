<template>
  <div v-if="!entries?.length" :style="dark ? darkEmpty : lightEmpty">
    <i class="fas fa-clock-rotate-left" style="font-size:28px;opacity:.3;display:block;margin-bottom:10px" />
    No changes
  </div>
  <div v-else :class="dark ? 'cl-wrap-dark' : 'cl-wrap-light'">
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead>
        <tr :style="dark ? 'background:rgba(255,255,255,.04)' : 'background:#f8fafc'">
          <th class="cl-th" style="width:120px">Time</th>
          <th class="cl-th">User</th>
          <th class="cl-th">Action</th>
          <th class="cl-th">Object</th>
          <th v-if="showDevice" class="cl-th">Device</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="c in entries" :key="c.id" :style="dark ? 'border-top:1px solid rgba(255,255,255,.04)' : 'border-top:1px solid #f1f5f9'">
          <td class="cl-td" :style="dark ? 'color:#64748b' : 'color:#94a3b8'">{{ fmtDt(c.created_at || c.ts) }}</td>
          <td class="cl-td" :style="dark ? 'color:#94a3b8' : 'color:#374151'">{{ c.username }}</td>
          <td class="cl-td">
            <span class="cl-action" :class="actionCls(c.action)">{{ c.action }}</span>
            <span style="font-size:9px;margin-left:3px" :style="dark ? 'color:#64748b' : 'color:#94a3b8'">{{ c.entity_type }}</span>
          </td>
          <td class="cl-td" style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" :style="dark ? 'color:#e2e8f0' : 'color:#374151'">{{ c.entity_name || '—' }}</td>
          <td v-if="showDevice" class="cl-td" style="font-size:11px" :style="dark ? 'color:#475569' : 'color:#94a3b8'">{{ c.device_name }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup>
defineProps({
  entries: { type: Array, default: () => [] },
  dark: { type: Boolean, default: false },
  showDevice: { type: Boolean, default: false },
})

const darkEmpty = 'background:#1e293b;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:40px 20px;text-align:center;color:#475569'
const lightEmpty = 'background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:40px 20px;text-align:center;color:#94a3b8'

function fmtDt(dt) {
  if (!dt) return ''
  return new Date(dt).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function actionCls(a) {
  if (!a) return ''
  const v = a.toLowerCase()
  if (v === 'create') return 'cl-create'
  if (v === 'delete') return 'cl-delete'
  if (v === 'update') return 'cl-update'
  if (v === 'toggle') return 'cl-toggle'
  return 'cl-other'
}
</script>

<style scoped>
.cl-wrap-dark { background:#1e293b;border:1px solid rgba(255,255,255,.07);border-radius:10px;overflow:hidden }
.cl-wrap-light { background:#fff;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden }
.cl-th { padding:8px 10px;color:#94a3b8;font-weight:600;text-align:left;white-space:nowrap }
.cl-td { padding:6px 10px }
.cl-action { display:inline-block;padding:1px 6px;border-radius:20px;font-size:9px;font-weight:700;text-transform:uppercase }
.cl-create { background:rgba(34,197,94,.15);color:#22c55e }
.cl-delete { background:rgba(239,68,68,.15);color:#ef4444 }
.cl-update { background:rgba(59,130,246,.15);color:#60a5fa }
.cl-toggle { background:rgba(139,92,246,.15);color:#a78bfa }
.cl-other  { background:rgba(100,116,139,.15);color:#94a3b8 }
</style>
