<template>
  <div class="app-topbar">
    <span class="topbar-title"><i class="fas fa-microscope" style="color:var(--accent);margin-right:6px" />Rule Analyzer</span>
    <div class="topbar-sep" />
    <select v-model="selectedDeviceId" class="form-select" style="width:200px;height:32px;font-size:12px;padding:0 8px">
      <option v-for="d in devices.devices" :key="d.id" :value="d.id">{{ d.name }}</option>
    </select>
    <div style="margin-left:auto;display:flex;gap:8px">
      <button class="btn-top primary" @click="runAnalysis" :disabled="running">
        <i class="fas fa-play" :class="{ 'fa-spin': running }" />
        {{ running ? 'Analyzing…' : 'Run Analysis' }}
      </button>
    </div>
  </div>
  <div class="app-content">
    <div v-if="!result && !running" class="empty-state">
      <i class="fas fa-microscope" />
      <div style="margin-top:8px">Select a device and run analysis to detect policy issues</div>
    </div>
    <div v-if="running" class="empty-state">
      <div class="spinner-ring" style="margin:0 auto 12px" />
      <div>Analyzing rules…</div>
    </div>
    <template v-if="result && !running">
      <!-- Summary -->
      <div style="display:flex;gap:12px;margin-bottom:16px">
        <StatCard title="Total Issues" :value="result.total_issues" icon="fas fa-exclamation-triangle" color="#ef4444" />
        <StatCard title="Shadow Rules" :value="result.shadow_count" icon="fas fa-ghost" color="#f59e0b" />
        <StatCard title="Duplicate Rules" :value="result.duplicate_count" icon="fas fa-copy" color="#8b5cf6" />
        <StatCard title="Unused Rules" :value="result.unused_count" icon="fas fa-eye-slash" color="#64748b" />
      </div>

      <!-- Issues list -->
      <div class="folder-card">
        <div class="folder-card-header">
          <span class="folder-card-title">Issues Found</span>
          <div style="margin-left:auto;display:flex;gap:4px">
            <button v-for="f in severityFilters" :key="f.key" class="btn-top" :class="{ primary: severityFilter === f.key }" @click="severityFilter = f.key" style="padding:3px 10px">
              {{ f.label }}
            </button>
          </div>
        </div>
        <div v-if="filteredIssues.length === 0" class="empty-state" style="padding:24px">No issues for selected filter</div>
        <div v-else>
          <div v-for="issue in filteredIssues" :key="issue.id" class="issue-item" :class="issue.severity">
            <div class="issue-badge" :class="issue.severity">{{ issue.severity }}</div>
            <div style="flex:1">
              <div style="font-weight:600;font-size:13px">{{ issue.title }}</div>
              <div style="font-size:12px;color:var(--text-muted);margin-top:2px">{{ issue.description }}</div>
              <div v-if="issue.rule_names?.length" style="font-size:11px;color:var(--accent);margin-top:4px">
                <i class="fas fa-link" /> {{ issue.rule_names.join(', ') }}
              </div>
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useDevicesStore } from '@/stores/devices'
import { useToastStore } from '@/stores/toast'
import { analyzerApi } from '@/api'
import StatCard from '@/components/StatCard.vue'

const devices = useDevicesStore()
const toast = useToastStore()

const selectedDeviceId = ref(null)
const result = ref(null)
const running = ref(false)
const severityFilter = ref('all')

const severityFilters = [
  { key: 'all', label: 'All' },
  { key: 'critical', label: 'Critical' },
  { key: 'warning', label: 'Warning' },
  { key: 'info', label: 'Info' },
]

const filteredIssues = computed(() => {
  if (!result.value?.issues) return []
  if (severityFilter.value === 'all') return result.value.issues
  return result.value.issues.filter((i) => i.severity === severityFilter.value)
})

async function runAnalysis() {
  if (!selectedDeviceId.value) return
  running.value = true
  try {
    const res = await analyzerApi.run({ device_id: selectedDeviceId.value })
    result.value = res.data
    toast.success(`Analysis complete: ${res.data.total_issues} issues found`)
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Analysis failed')
  } finally {
    running.value = false
  }
}

async function loadCached() {
  if (!selectedDeviceId.value) return
  try {
    const res = await analyzerApi.cached({ device_id: selectedDeviceId.value })
    if (res.data?.issues) result.value = res.data
  } catch {
    // no cached result
  }
}

onMounted(async () => {
  await devices.fetchDevices()
  if (devices.currentDevice) {
    selectedDeviceId.value = devices.currentDevice.id
    await loadCached()
  }
})
</script>

<style scoped>
.issue-item {
  display: flex; align-items: flex-start; gap: 12px;
  padding: 12px 16px; border-bottom: 1px solid var(--border);
}
.issue-item:last-child { border-bottom: none; }
.issue-badge {
  font-size: 10px; font-weight: 700; text-transform: uppercase;
  padding: 2px 8px; border-radius: 4px; flex-shrink: 0; letter-spacing: .5px;
}
.issue-badge.critical { background: #fee2e2; color: #991b1b; }
.issue-badge.warning  { background: #fef9c3; color: #854d0e; }
.issue-badge.info     { background: #eff6ff; color: #1d4ed8; }
</style>
