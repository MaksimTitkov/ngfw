<template>
  <div class="app-topbar">
    <span class="topbar-title"><i class="fas fa-list-alt" style="color:#3b82f6;margin-right:6px" />Logs &amp; Monitoring</span>
    <div class="topbar-sep" />
    <!-- Log type tabs -->
    <div style="display:flex;gap:4px">
      <button v-for="tab in logTabs" :key="tab.key" @click="setTab(tab.key)"
              :class="['log-tab', activeTab===tab.key?'log-tab-active':'']">
        <i :class="`fas ${tab.icon} me-1`" />{{ tab.label }}
      </button>
    </div>
    <div class="topbar-sep" />
    <select v-model="selectedDeviceId" class="form-select" style="width:180px;height:32px;font-size:12px;padding:0 8px">
      <option v-for="d in devicesStore.devices" :key="d.id" :value="d.id">{{ d.name }}</option>
    </select>
  </div>

  <!-- Fetch panel -->
  <div style="padding:12px 16px;background:#f8fafc;border-bottom:1px solid #e2e8f0;flex-shrink:0">
    <div style="display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end">
      <div>
        <div class="fetch-label">Fetch From</div>
        <input v-model="fetchFrom" type="datetime-local" class="fetch-input" />
      </div>
      <div>
        <div class="fetch-label">Fetch To</div>
        <input v-model="fetchTo" type="datetime-local" class="fetch-input" />
      </div>
      <div>
        <div class="fetch-label">Quick Fetch</div>
        <div style="display:flex;gap:4px;flex-wrap:wrap">
          <button v-for="h in [1,2,4,6,12,24]" :key="h" @click="quickFetch(h)"
                  :class="['period-btn', activePeriod===h?'period-active':'']">
            {{ h }}h<i v-if="h>=12" class="fas fa-triangle-exclamation" style="color:#f59e0b;font-size:9px;margin-left:2px" />
          </button>
        </div>
      </div>
      <div v-if="activeTab!=='audit'">
        <div class="fetch-label">Src IP</div>
        <input v-model="filters.src_ip" type="text" placeholder="10.0.0.1" class="fetch-input" style="width:120px" />
      </div>
      <div v-if="activeTab!=='audit'">
        <div class="fetch-label">Dst IP</div>
        <input v-model="filters.dst_ip" type="text" placeholder="8.8.8.8" class="fetch-input" style="width:120px" />
      </div>
      <div v-if="activeTab!=='audit'">
        <div class="fetch-label">Dst Port</div>
        <input v-model.number="filters.dst_port" type="number" placeholder="443" class="fetch-input" style="width:80px" />
      </div>
      <div v-if="activeTab!=='audit'">
        <div class="fetch-label">Action</div>
        <select v-model="filters.action" class="fetch-input">
          <option value="">Any</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
          <option value="drop">Drop</option>
        </select>
      </div>
      <button @click="doFetch" :disabled="fetching" class="btn-fetch">
        <i class="fas fa-cloud-download-alt" /> {{ fetching?'Fetching…':'Fetch from NGFW' }}
      </button>
    </div>

    <!-- Cache status bar -->
    <div style="display:flex;align-items:center;gap:12px;margin-top:10px;flex-wrap:wrap">
      <span style="font-size:12px;color:#64748b">
        <i class="fas fa-info-circle me-1" style="color:#94a3b8" />{{ statusText }}
      </span>
      <div style="display:flex;gap:6px;margin-left:auto">
        <button @click="applyFilters" class="cache-btn" style="border-color:#93c5fd;background:#eff6ff;color:#1d4ed8"><i class="fas fa-filter me-1" />Search in Cache</button>
        <button @click="exportCSV" class="cache-btn" style="border-color:#a7f3d0;background:#f0fdf4;color:#065f46"><i class="fas fa-file-csv me-1" />Export CSV</button>
        <button @click="clearCache" class="cache-btn" style="border-color:#fca5a5;background:#fff1f2;color:#991b1b"><i class="fas fa-trash me-1" />Clear Cache</button>
        <button @click="showStats=!showStats" :class="['cache-btn', showStats?'stats-active':'']" style="border-color:#c4b5fd;background:#f5f3ff;color:#5b21b6"><i class="fas fa-chart-bar me-1" />Stats</button>
      </div>
    </div>

    <!-- Browse time filter -->
    <div style="display:flex;align-items:center;gap:8px;margin-top:8px;flex-wrap:wrap">
      <span style="font-size:11px;font-weight:600;color:#64748b">Filter in cache:</span>
      <div><span style="font-size:10px;color:#94a3b8;margin-right:3px">From</span><input v-model="browseFrom" type="datetime-local" style="padding:3px 6px;border:1px solid #e2e8f0;border-radius:5px;font-size:11px;outline:none" /></div>
      <div><span style="font-size:10px;color:#94a3b8;margin-right:3px">To</span><input v-model="browseTo" type="datetime-local" style="padding:3px 6px;border:1px solid #e2e8f0;border-radius:5px;font-size:11px;outline:none" /></div>
      <button @click="applyFilters" style="padding:3px 10px;border-radius:6px;border:1px solid #e2e8f0;background:#fff;font-size:11px;font-weight:600;cursor:pointer">Apply</button>
      <button @click="browseFrom='';browseTo='';applyFilters()" style="padding:3px 8px;border-radius:6px;border:1px solid #e2e8f0;background:#fff;font-size:11px;color:#64748b;cursor:pointer">Reset</button>
    </div>
  </div>

  <!-- Stats panel -->
  <div v-if="showStats" style="padding:16px;background:#0f172a;border-bottom:1px solid rgba(255,255,255,.06);overflow:auto;max-height:300px">
    <div v-if="statsLoading" style="text-align:center;padding:32px;color:#475569"><i class="fas fa-circle-notch fa-spin me-2" />Loading stats…</div>
    <div v-else-if="stats" style="display:flex;flex-wrap:wrap;gap:16px">
      <div v-for="(section, title) in stats" :key="title" class="stats-section">
        <div class="stats-title"><i class="fas fa-chart-bar" style="color:#60a5fa" />{{ title }}</div>
        <div v-for="item in section.slice(0,10)" :key="item.label" class="bar-row">
          <div class="bar-label" :title="item.label">{{ item.label }}</div>
          <div class="bar-track"><div class="bar-fill" :style="`width:${item.pct||0}%;background:${item.color||'#3b82f6'}`" /></div>
          <div class="bar-count">{{ item.count }}</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Log table -->
  <div style="flex:1;overflow:auto">
    <table class="rules-table" style="min-width:900px">
      <thead>
        <tr><th v-for="col in columns" :key="col.h">{{ col.h }}</th><th></th></tr>
      </thead>
      <tbody>
        <tr v-if="!rows.length">
          <td :colspan="columns.length+1" style="text-align:center;padding:48px;color:#94a3b8;font-size:13px">
            <i class="fas fa-cloud-download-alt" style="font-size:20px;display:block;margin-bottom:8px" />Use "Fetch from NGFW" to load logs into cache
          </td>
        </tr>
        <tr v-for="(row, i) in rows" :key="i" @click="rawLog=row" style="cursor:pointer">
          <td v-for="col in columns" :key="col.h" style="font-size:11px;white-space:nowrap" v-html="fmtCell(row, col)" />
          <td><button class="row-btn" @click.stop="rawLog=row" title="Raw"><i class="fas fa-code" /></button></td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- Load more -->
  <div v-if="total>rows.length" style="padding:10px 16px;background:#f8fafc;border-top:1px solid #e2e8f0;display:flex;align-items:center;gap:12px">
    <span style="font-size:12px;color:#64748b">Showing {{ rows.length }} of {{ total }}</span>
    <button @click="loadMore" style="padding:4px 14px;border-radius:6px;border:1px solid #e2e8f0;background:#fff;font-size:12px;font-weight:600;cursor:pointer">
      <i class="fas fa-chevron-down me-1" />Load More (100)
    </button>
  </div>

  <!-- Raw log modal -->
  <div v-if="rawLog" style="position:fixed;inset:0;z-index:9000;background:rgba(15,23,42,.65);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center" @click.self="rawLog=null">
    <div style="background:#0f172a;border-radius:12px;width:90%;max-width:800px;max-height:85vh;display:flex;flex-direction:column;box-shadow:0 24px 60px rgba(0,0,0,.5)">
      <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid #1e293b">
        <span style="color:#60a5fa;font-size:13px;font-weight:700"><i class="fas fa-code me-2" />Raw Log Entry</span>
        <button @click="rawLog=null" style="background:none;border:none;color:#64748b;cursor:pointer;font-size:16px">×</button>
      </div>
      <div style="overflow:auto;padding:16px;flex:1">
        <pre style="color:#94a3b8;font-size:12px;margin:0;white-space:pre-wrap;word-break:break-all;font-family:monospace">{{ JSON.stringify(rawLog, null, 2) }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { useDevicesStore } from '@/stores/devices'
import { useToastStore } from '@/stores/toast'
import { logsApi } from '@/api'

const devicesStore = useDevicesStore()
const toast = useToastStore()

const selectedDeviceId = ref(null)
const activeTab = ref('traffic')
const activePeriod = ref(1)
const fetchFrom = ref('')
const fetchTo = ref('')
const browseFrom = ref('')
const browseTo = ref('')
const filters = ref({ src_ip:'', dst_ip:'', dst_port:'', action:'' })
const fetching = ref(false)
const rows = ref([])
const total = ref(0)
const offset = ref(0)
const statusText = ref('No data cached for this log type.')
const showStats = ref(false)
const stats = ref(null)
const statsLoading = ref(false)
const rawLog = ref(null)

const logTabs = [
  { key:'traffic', label:'Traffic', icon:'fa-arrow-right-arrow-left' },
  { key:'ips',     label:'IPS',     icon:'fa-shield-virus' },
  { key:'av',      label:'Antivirus',icon:'fa-bug' },
  { key:'audit',   label:'Audit',   icon:'fa-user-shield' },
]

const COLS = {
  traffic: [
    {h:'Time',     f:['entryGeneration','entryReceived','sessionStart']},
    {h:'Context',  f:['contextName','deviceName']},
    {h:'Src IP',   f:['srcAddr']},
    {h:'Src Port', f:['srcPort']},
    {h:'Dst IP',   f:['dstAddr']},
    {h:'Dst Port', f:['dstPort']},
    {h:'Proto',    f:['ipProtocol'], fmt:'proto'},
    {h:'App',      f:['app']},
    {h:'Action',   f:['action'], fmt:'action'},
    {h:'Rule',     f:['securityRuleName']},
    {h:'Sent',     f:['bytesSent'], fmt:'bytes'},
    {h:'Recv',     f:['bytesReceived'], fmt:'bytes'},
  ],
  ips: [
    {h:'Time',     f:['entryGeneration','entryReceived']},
    {h:'Context',  f:['contextName','deviceName']},
    {h:'Src IP',   f:['srcAddr']},
    {h:'Src Port', f:['srcPort']},
    {h:'Dst IP',   f:['dstAddr']},
    {h:'Dst Port', f:['dstPort']},
    {h:'Threat',   f:['threatName']},
    {h:'Severity', f:['threatSeverity'], fmt:'severity'},
    {h:'Action',   f:['action'], fmt:'action'},
    {h:'Proto',    f:['ipProtocol'], fmt:'proto'},
  ],
  av: [
    {h:'Time',     f:['entryGeneration','entryReceived']},
    {h:'Context',  f:['contextName','deviceName']},
    {h:'Src IP',   f:['srcAddr']},
    {h:'Dst IP',   f:['dstAddr']},
    {h:'Threat',   f:['threatName']},
    {h:'File',     f:['fileName']},
    {h:'Action',   f:['action'], fmt:'action'},
  ],
  audit: [
    {h:'Time',     f:['generateTime']},
    {h:'Admin',    f:['adminDisplayName','adminLogin']},
    {h:'Action',   f:['action']},
    {h:'Source IP',f:['sourceAddress']},
    {h:'Args',     f:['queryArgs']},
    {h:'Result',   f:['result']},
  ],
}

const columns = computed(() => COLS[activeTab.value] || [])

function setTab(t) {
  activeTab.value = t
  rows.value = []; total.value = 0; offset.value = 0
  loadStatus()
}

function toLocalInput(date) {
  const pad = (n) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

function setPeriod(h) {
  activePeriod.value = h
  const now = new Date()
  fetchTo.value = toLocalInput(now)
  fetchFrom.value = toLocalInput(new Date(now - h*3600*1000))
}

async function quickFetch(h) {
  setPeriod(h)
  await doFetch()
}

async function doFetch() {
  if (!selectedDeviceId.value) { toast.error('Select a device first'); return }
  fetching.value = true
  try {
    await logsApi.fetch({
      device_group_id: selectedDeviceId.value,
      log_type: activeTab.value,
      from: fetchFrom.value,
      to: fetchTo.value,
      src_ip: filters.value.src_ip || undefined,
      dst_ip: filters.value.dst_ip || undefined,
      dst_port: filters.value.dst_port || undefined,
      action: filters.value.action || undefined,
    })
    toast.success('Logs fetched')
    await loadStatus()
    await applyFilters()
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Fetch failed')
  } finally {
    fetching.value = false
  }
}

async function loadStatus() {
  try {
    const res = await logsApi.status({ device_group_id: selectedDeviceId.value })
    const s = res.data?.types?.[activeTab.value] || {}
    if (s.count) statusText.value = `${s.count} entries cached (${s.from?.slice(0,16)} – ${s.to?.slice(0,16)})`
    else statusText.value = 'No data cached for this log type.'
  } catch { /**/ }
}

async function applyFilters() {
  if (!selectedDeviceId.value) return
  try {
    const res = await logsApi.query({
      device_group_id: selectedDeviceId.value,
      log_type: activeTab.value,
      from: browseFrom.value || undefined,
      to: browseTo.value || undefined,
      limit: 100, offset: 0,
    })
    rows.value = res.data?.items || res.data || []
    total.value = res.data?.total || rows.value.length
    offset.value = rows.value.length
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Query failed')
  }
}

async function loadMore() {
  try {
    const res = await logsApi.query({
      device_group_id: selectedDeviceId.value,
      log_type: activeTab.value,
      from: browseFrom.value || undefined,
      to: browseTo.value || undefined,
      limit: 100, offset: offset.value,
    })
    const newItems = res.data?.items || res.data || []
    rows.value.push(...newItems)
    offset.value += newItems.length
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Load more failed')
  }
}

async function clearCache() {
  try {
    await logsApi.clear({ device_group_id: selectedDeviceId.value, log_type: activeTab.value })
    toast.success('Cache cleared')
    rows.value = []; total.value = 0
    statusText.value = 'No data cached for this log type.'
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Clear failed')
  }
}

async function exportCSV() {
  window.location = `/api/v1/logs/export?device_group_id=${selectedDeviceId.value}&log_type=${activeTab.value}`
}

watch(showStats, async (v) => {
  if (v && !stats.value) {
    statsLoading.value = true
    try {
      const res = await logsApi.topStats({ device_group_id: selectedDeviceId.value, log_type: activeTab.value })
      stats.value = res.data
    } catch { /**/ } finally { statsLoading.value = false }
  }
})

function getVal(row, fields) {
  for (const f of fields) { if (row[f] !== undefined && row[f] !== null && row[f] !== '') return String(row[f]) }
  return '—'
}

function fmtCell(row, col) {
  const val = getVal(row, col.f)
  if (col.fmt === 'action') {
    const cls = { allow:'a-allow', pass:'a-allow', deny:'a-deny', drop:'a-drop' }[val?.toLowerCase()] || 'a-other'
    return `<span class="${cls}">${val}</span>`
  }
  if (col.fmt === 'severity') {
    const cls = { critical:'sev-critical', high:'sev-high', medium:'sev-medium', low:'sev-low' }[val?.toLowerCase()] || 'sev-other'
    return `<span class="${cls}">${val}</span>`
  }
  if (col.fmt === 'bytes') {
    const n = parseInt(val)
    if (isNaN(n)) return val
    if (n >= 1048576) return `${(n/1048576).toFixed(1)} MB`
    if (n >= 1024) return `${(n/1024).toFixed(0)} KB`
    return `${n} B`
  }
  if (col.fmt === 'proto') {
    const m = {1:'ICMP',6:'TCP',17:'UDP',47:'GRE',50:'ESP',51:'AH'}
    return m[parseInt(val)] || val
  }
  return val
}

onMounted(async () => {
  await devicesStore.fetchDevices()
  if (devicesStore.currentDevice) {
    selectedDeviceId.value = devicesStore.currentDevice.id
    setPeriod(1)
    loadStatus()
  }
})
</script>

<style scoped>
.log-tab { padding:4px 12px;border-radius:6px;border:none;font-size:11px;font-weight:600;cursor:pointer;transition:.15s;background:#f1f5f9;color:#64748b }
.log-tab-active { background:#3b82f6;color:#fff }
.log-tab:hover:not(.log-tab-active) { background:#e2e8f0 }
.period-btn { padding:4px 10px;border-radius:6px;border:1px solid #e2e8f0;font-size:11px;font-weight:600;cursor:pointer;transition:.15s;background:#fff;color:#374151 }
.period-active { background:#3b82f6!important;color:#fff!important;border-color:#3b82f6!important }
.fetch-label { font-size:10px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px }
.fetch-input { padding:4px 8px;border:1px solid #e2e8f0;border-radius:6px;font-size:12px;outline:none;background:#fff }
.btn-fetch { padding:5px 16px;border-radius:8px;border:none;background:#3b82f6;color:#fff;font-size:12px;font-weight:700;cursor:pointer;align-self:flex-end;display:flex;align-items:center;gap:6px }
.btn-fetch:hover { background:#2563eb }
.btn-fetch:disabled { opacity:.6;cursor:not-allowed }
.cache-btn { padding:3px 10px;border-radius:6px;border:1px solid;font-size:11px;font-weight:600;cursor:pointer }
.stats-active { background:#5b21b6!important;color:#fff!important;border-color:#5b21b6!important }
.stats-section { background:#1e293b;border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:14px 18px;min-width:200px }
.stats-title { font-size:11px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:.05em;margin-bottom:12px;display:flex;align-items:center;gap:6px }
.bar-row { display:flex;align-items:center;gap:8px;margin-bottom:5px }
.bar-label { font-size:11px;color:#94a3b8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;width:140px;flex-shrink:0 }
.bar-track { flex:1;height:12px;background:rgba(255,255,255,.05);border-radius:6px;overflow:hidden }
.bar-fill { height:100%;border-radius:6px;transition:width .4s ease }
.bar-count { font-size:11px;font-weight:700;color:#cbd5e1;width:42px;text-align:right;flex-shrink:0 }
.a-allow,.a-pass { display:inline-block;padding:1px 7px;border-radius:20px;font-size:10px;font-weight:700;background:#dcfce7;color:#166534 }
.a-deny  { display:inline-block;padding:1px 7px;border-radius:20px;font-size:10px;font-weight:700;background:#fee2e2;color:#991b1b }
.a-drop  { display:inline-block;padding:1px 7px;border-radius:20px;font-size:10px;font-weight:700;background:#fef3c7;color:#92400e }
.a-other { display:inline-block;padding:1px 7px;border-radius:20px;font-size:10px;font-weight:700;background:#e0e7ff;color:#3730a3 }
.sev-critical { display:inline-block;padding:1px 7px;border-radius:20px;font-size:10px;font-weight:700;background:#fee2e2;color:#991b1b }
.sev-high     { display:inline-block;padding:1px 7px;border-radius:20px;font-size:10px;font-weight:700;background:#fed7aa;color:#92400e }
.sev-medium   { display:inline-block;padding:1px 7px;border-radius:20px;font-size:10px;font-weight:700;background:#fef3c7;color:#92400e }
.sev-low      { display:inline-block;padding:1px 7px;border-radius:20px;font-size:10px;font-weight:700;background:#dcfce7;color:#166534 }
.sev-other    { display:inline-block;padding:1px 7px;border-radius:20px;font-size:10px;font-weight:700;background:#f1f5f9;color:#64748b }
.row-btn { padding:3px 6px;border:none;background:transparent;cursor:pointer;color:var(--text-muted);border-radius:4px;font-size:11px }
.row-btn:hover { background:var(--border) }
</style>
