<template>
  <div class="app-topbar">
    <span class="topbar-title"><i class="fas fa-clock-rotate-left" style="color:var(--accent);margin-right:6px" />Change Log</span>
    <div class="topbar-sep" />
    <select v-model="selectedDeviceId" class="form-select" style="width:200px;height:32px;font-size:12px;padding:0 8px" @change="loadChangelog">
      <option v-for="d in devices.devices" :key="d.id" :value="d.id">{{ d.name }}</option>
    </select>
    <div style="margin-left:auto;display:flex;gap:8px">
      <input v-model="search" class="form-control" placeholder="Search changes…" style="width:220px;height:32px;font-size:12px" />
    </div>
  </div>
  <div class="app-content">
    <div v-if="loading" class="empty-state"><div class="spinner-ring" style="margin:0 auto 12px" /></div>
    <div v-else-if="filtered.length === 0" class="empty-state">
      <i class="fas fa-clock-rotate-left" /><div style="margin-top:8px">No changes found</div>
    </div>
    <div v-else class="folder-card">
      <table class="rules-table">
        <thead>
          <tr>
            <th style="width:140px">Time</th>
            <th style="width:80px">User</th>
            <th style="width:100px">Action</th>
            <th>Object</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="entry in filtered" :key="entry.id">
            <td style="font-size:11px;color:var(--text-muted);white-space:nowrap">{{ formatDt(entry.created_at) }}</td>
            <td style="font-size:12px;font-weight:600">{{ entry.username }}</td>
            <td>
              <span class="action-badge" :class="actionClass(entry.action)">{{ entry.action }}</span>
            </td>
            <td class="rule-name" style="font-size:12px">{{ entry.object_name }}</td>
            <td style="font-size:11px;color:var(--text-muted)">{{ entry.detail }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useDevicesStore } from '@/stores/devices'
import { useToastStore } from '@/stores/toast'
import { changelogApi } from '@/api'

const devices = useDevicesStore()
const toast = useToastStore()

const selectedDeviceId = ref(null)
const entries = ref([])
const loading = ref(false)
const search = ref('')

const filtered = computed(() => {
  const q = search.value.toLowerCase().trim()
  if (!q) return entries.value
  return entries.value.filter(
    (e) => e.object_name?.toLowerCase().includes(q) || e.username?.toLowerCase().includes(q) || e.detail?.toLowerCase().includes(q)
  )
})

async function loadChangelog() {
  if (!selectedDeviceId.value) return
  loading.value = true
  try {
    const res = await changelogApi.query({ device_id: selectedDeviceId.value, limit: 500 })
    entries.value = res.data?.items || res.data || []
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Failed to load changelog')
  } finally {
    loading.value = false
  }
}

function formatDt(dt) {
  if (!dt) return ''
  return new Date(dt).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function actionClass(action) {
  if (!action) return ''
  const a = action.toLowerCase()
  if (a.includes('create') || a.includes('add')) return 'allow'
  if (a.includes('delete') || a.includes('remove')) return 'drop'
  return 'deny'
}

onMounted(async () => {
  await devices.fetchDevices()
  if (devices.currentDevice) {
    selectedDeviceId.value = devices.currentDevice.id
    await loadChangelog()
  }
})
</script>
