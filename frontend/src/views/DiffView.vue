<template>
  <div class="app-topbar">
    <span class="topbar-title"><i class="fas fa-code-compare" style="color:var(--accent);margin-right:6px" />Policy Diff</span>
    <div style="margin-left:auto;display:flex;align-items:center;gap:8px">
      <select v-model="device1" class="form-select" style="width:200px;height:32px;font-size:12px;padding:0 8px">
        <option value="">Device A</option>
        <option v-for="d in devices.devices" :key="d.id" :value="d.id">{{ d.name }}</option>
      </select>
      <i class="fas fa-arrows-left-right" style="color:var(--text-muted)" />
      <select v-model="device2" class="form-select" style="width:200px;height:32px;font-size:12px;padding:0 8px">
        <option value="">Device B</option>
        <option v-for="d in devices.devices" :key="d.id" :value="d.id">{{ d.name }}</option>
      </select>
      <button class="btn-top primary" @click="runDiff" :disabled="!device1 || !device2 || loading">
        <i class="fas fa-play" /> Compare
      </button>
    </div>
  </div>
  <div class="app-content">
    <div v-if="!result && !loading" class="empty-state">
      <i class="fas fa-code-compare" /><div style="margin-top:8px">Select two devices to compare their policies</div>
    </div>
    <div v-if="loading" class="empty-state">
      <div class="spinner-ring" style="margin:0 auto 12px" /><div>Comparing…</div>
    </div>
    <template v-if="result && !loading">
      <div style="display:flex;gap:12px;margin-bottom:16px">
        <StatCard title="Added" :value="result.added_count" icon="fas fa-plus" color="#22c55e" />
        <StatCard title="Removed" :value="result.removed_count" icon="fas fa-minus" color="#ef4444" />
        <StatCard title="Modified" :value="result.modified_count" icon="fas fa-pen" color="#f59e0b" />
        <StatCard title="Identical" :value="result.identical_count" icon="fas fa-equals" color="#64748b" />
      </div>
      <div class="folder-card">
        <div class="folder-card-header">
          <span class="folder-card-title">Rule Differences</span>
          <div style="margin-left:auto;display:flex;gap:4px">
            <button v-for="f in diffFilters" :key="f.key" class="btn-top" :class="{ primary: diffFilter === f.key }" @click="diffFilter = f.key" style="padding:3px 10px">
              {{ f.label }}
            </button>
          </div>
        </div>
        <table class="rules-table">
          <thead><tr><th>Status</th><th>Rule Name</th><th>Detail</th></tr></thead>
          <tbody>
            <tr v-for="item in filteredDiff" :key="item.rule_id">
              <td><span class="action-badge" :class="item.status">{{ item.status }}</span></td>
              <td class="rule-name">{{ item.rule_name }}</td>
              <td style="font-size:11px;color:var(--text-muted)">{{ item.detail }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useDevicesStore } from '@/stores/devices'
import { useToastStore } from '@/stores/toast'
import { diffApi } from '@/api'
import StatCard from '@/components/StatCard.vue'

const devices = useDevicesStore()
const toast = useToastStore()

const device1 = ref('')
const device2 = ref('')
const result = ref(null)
const loading = ref(false)
const diffFilter = ref('all')

const diffFilters = [
  { key: 'all', label: 'All' },
  { key: 'added', label: 'Added' },
  { key: 'removed', label: 'Removed' },
  { key: 'modified', label: 'Modified' },
]

const filteredDiff = computed(() => {
  if (!result.value?.items) return []
  if (diffFilter.value === 'all') return result.value.items
  return result.value.items.filter((i) => i.status === diffFilter.value)
})

async function runDiff() {
  loading.value = true
  try {
    const res = await diffApi.compare({ device_id_a: device1.value, device_id_b: device2.value })
    result.value = res.data
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Diff failed')
  } finally {
    loading.value = false
  }
}

onMounted(() => devices.fetchDevices())
</script>
