<template>
  <div class="app-topbar">
    <span class="topbar-title"><i class="fas fa-cube" style="color:var(--accent);margin-right:6px" />Objects</span>
    <div class="topbar-sep" />
    <select v-model="selectedDeviceId" class="form-select" style="width:200px;height:32px;font-size:12px;padding:0 8px" @change="loadObjects">
      <option v-for="d in devices.devices" :key="d.id" :value="d.id">{{ d.name }}</option>
    </select>
    <div class="topbar-sep" />
    <div style="display:flex;gap:2px">
      <button v-for="t in objectTypes" :key="t.key" class="btn-top" :class="{ primary: activeType === t.key }" @click="activeType = t.key">
        {{ t.label }}
      </button>
    </div>
    <div style="margin-left:auto">
      <button v-if="!auth.isReadOnly" class="btn-top primary" @click="showCreate = true"><i class="fas fa-plus" /> Add Object</button>
    </div>
  </div>
  <div class="app-content">
    <div style="margin-bottom:12px;display:flex;gap:8px">
      <input v-model="search" class="form-control" placeholder="Search objects…" style="max-width:320px" />
    </div>

    <div v-if="loading" class="empty-state"><div class="spinner-ring" style="margin:0 auto 12px" /></div>
    <div v-else-if="filtered.length === 0" class="empty-state">
      <i class="fas fa-cube" /><div style="margin-top:8px">No objects found</div>
    </div>
    <div v-else class="folder-card">
      <table class="rules-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Value</th>
            <th>Device</th>
            <th>Used in rules</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="obj in filtered" :key="obj.id">
            <td class="rule-name">{{ obj.name }}</td>
            <td><span class="obj-tag" :class="typeClass(obj.type)">{{ obj.type }}</span></td>
            <td style="font-size:11px;color:var(--text-muted)">{{ obj.value || obj.ip || obj.cidr || '—' }}</td>
            <td style="font-size:11px">{{ obj.device_name || '—' }}</td>
            <td style="font-size:11px;color:var(--text-muted)">{{ obj.rule_count ?? '—' }}</td>
            <td>
              <div v-if="!auth.isReadOnly" style="display:flex;gap:4px;justify-content:flex-end">
                <button class="row-btn" @click="editObj = obj" title="Edit"><i class="fas fa-pen" /></button>
                <button class="row-btn danger" @click="deleteObject(obj.id)" title="Delete"><i class="fas fa-trash" /></button>
              </div>
            </td>
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
import { useAuthStore } from '@/stores/auth'
import { objectsApi } from '@/api'

const devices = useDevicesStore()
const toast = useToastStore()
const auth = useAuthStore()

const selectedDeviceId = ref(null)
const objects = ref([])
const loading = ref(false)
const search = ref('')
const activeType = ref('all')
const showCreate = ref(false)
const editObj = ref(null)

const objectTypes = [
  { key: 'all', label: 'All' },
  { key: 'ip', label: 'IP/Network' },
  { key: 'service', label: 'Service' },
  { key: 'app', label: 'Application' },
  { key: 'url', label: 'URL' },
  { key: 'user', label: 'User' },
]

const filtered = computed(() => {
  let list = objects.value
  if (activeType.value !== 'all') list = list.filter((o) => o.type === activeType.value)
  const q = search.value.toLowerCase().trim()
  if (q) list = list.filter((o) => o.name?.toLowerCase().includes(q) || o.value?.toLowerCase().includes(q))
  return list
})

async function loadObjects() {
  if (!selectedDeviceId.value) return
  loading.value = true
  try {
    const res = await objectsApi.list({ device_id: selectedDeviceId.value })
    objects.value = res.data
  } catch (e) {
    toast.error('Failed to load objects: ' + (e.response?.data?.detail || e.message))
  } finally {
    loading.value = false
  }
}

async function deleteObject(id) {
  try {
    await objectsApi.delete({ object_id: id })
    toast.success('Object deleted')
    await loadObjects()
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Delete failed')
  }
}

function typeClass(type) {
  return { ip: '', service: 'service', app: 'app', url: 'url' }[type] || ''
}

onMounted(async () => {
  await devices.fetchDevices()
  if (devices.currentDevice) {
    selectedDeviceId.value = devices.currentDevice.id
    await loadObjects()
  }
})
</script>

<style scoped>
.row-btn { padding: 3px 6px; border: none; background: transparent; cursor: pointer; color: var(--text-muted); border-radius: 4px; font-size: 11px; transition: all .12s; }
.row-btn:hover { background: var(--border); color: var(--text); }
.row-btn.danger:hover { background: #fee2e2; color: var(--danger); }
</style>
