<template>
  <div class="app-topbar">
    <span class="topbar-title"><i class="fas fa-magnifying-glass" style="color:#3b82f6;margin-right:6px" />Search</span>
    <div class="topbar-sep" />
    <span style="font-size:11px;color:#475569">Ctrl+K</span>
  </div>

  <div class="app-content" style="padding:20px">
    <!-- Search bar -->
    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;background:#1e293b;border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:16px 18px;margin-bottom:20px">
      <div style="position:relative;flex:1;min-width:280px">
        <i class="fas fa-magnifying-glass" style="position:absolute;left:12px;top:50%;transform:translateY(-50%);color:#475569;font-size:14px" />
        <input
          v-model="query" ref="inputRef" autofocus
          placeholder="Search rules by name, IP, port…"
          @keydown.enter="doSearch"
          style="width:100%;padding:9px 12px 9px 36px;border:1px solid rgba(255,255,255,.1);border-radius:8px;background:#0f172a;color:#e2e8f0;font-size:14px;outline:none"
        />
      </div>

      <!-- Mode selector -->
      <div style="display:flex;gap:4px">
        <button v-for="m in modes" :key="m.key" @click="mode=m.key;doSearch()"
                :style="`padding:7px 14px;border-radius:7px;font-size:12px;font-weight:600;border:none;cursor:pointer;transition:.15s;background:${mode===m.key?'rgba(59,130,246,.3)':'rgba(255,255,255,.06)'};color:${mode===m.key?'#60a5fa':'#64748b'}`">
          <i :class="`fas ${m.icon} me-1`" />{{ m.key.toUpperCase() }}
        </button>
      </div>

      <!-- Device filter -->
      <select v-model="selectedDeviceId" style="padding:7px 12px;border-radius:7px;font-size:12px;background:#0f172a;border:1px solid rgba(255,255,255,.1);color:#e2e8f0">
        <option value="">All Devices</option>
        <option v-for="d in devicesStore.devices" :key="d.id" :value="d.id">{{ d.name }}</option>
      </select>

      <button @click="doSearch" :disabled="searching"
              style="padding:8px 22px;background:linear-gradient(135deg,#1d4ed8,#3b82f6);color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer">
        {{ searching ? '…' : 'Search' }}
      </button>
    </div>

    <!-- Results -->
    <template v-if="searched">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
        <span style="color:#94a3b8;font-size:13px">
          <template v-if="results.length">
            <b style="color:#e2e8f0">{{ results.length }}</b> results for <b style="color:#60a5fa">{{ query }}</b>
          </template>
          <template v-else>No results for <b style="color:#60a5fa">{{ query }}</b></template>
        </span>
        <span v-if="results.length" style="background:rgba(59,130,246,.15);color:#60a5fa;font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px">
          {{ mode.toUpperCase() }} mode
        </span>
      </div>

      <div v-if="results.length" style="background:#1e293b;border:1px solid rgba(255,255,255,.07);border-radius:10px;overflow:hidden">
        <table class="rules-table" style="width:100%">
          <thead>
            <tr>
              <th style="width:32%">Rule Name</th>
              <th style="width:70px">Action</th>
              <th style="width:60px">Status</th>
              <th>Folder</th>
              <th>Device</th>
              <th>Match</th>
              <th style="width:60px"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in results" :key="r.id || r.name"
                style="border-top:1px solid rgba(255,255,255,.04);transition:.15s"
                @mouseenter="e=>e.currentTarget.style.background='rgba(255,255,255,.03)'"
                @mouseleave="e=>e.currentTarget.style.background=''">
              <td><div style="font-weight:600;font-size:13px;color:#e2e8f0">{{ r.name }}</div></td>
              <td>
                <span :style="`display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;background:${actionBg(r.action)};color:${actionColor(r.action)}`">
                  {{ r.action }}
                </span>
              </td>
              <td>
                <span :style="`color:${r.enabled?'#22c55e':'#64748b'};font-size:11px;font-weight:600`">
                  <i class="fas fa-circle" style="font-size:8px" /> {{ r.enabled ? 'ON' : 'OFF' }}
                </span>
              </td>
              <td style="color:#94a3b8;font-size:12px"><i class="fas fa-folder" style="font-size:10px;margin-right:4px;color:#475569" />{{ r.folder || '—' }}</td>
              <td style="color:#94a3b8;font-size:12px">{{ r.device }}</td>
              <td style="color:#64748b;font-size:11px;font-style:italic">{{ r.match }}</td>
              <td style="text-align:right;padding-right:10px">
                <router-link v-if="r.folder_id" :to="`/?folder_id=${r.folder_id}`"
                             style="display:inline-flex;align-items:center;gap:4px;padding:3px 8px;border-radius:5px;background:rgba(59,130,246,.1);color:#60a5fa;font-size:11px;text-decoration:none;font-weight:600">
                  <i class="fas fa-arrow-right" style="font-size:9px" />
                </router-link>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-if="results.length >= 300" style="text-align:center;color:#64748b;font-size:12px;padding:8px;border-top:1px solid rgba(255,255,255,.04)">
          <i class="fas fa-info-circle" /> Results capped at 300. Refine your search.
        </div>
      </div>

      <div v-else style="background:#1e293b;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:48px 20px;text-align:center;color:#475569">
        <i class="fas fa-magnifying-glass" style="font-size:36px;opacity:.2;display:block;margin-bottom:14px" />
        <div style="font-size:14px;margin-bottom:6px">No matching rules found</div>
        <div style="font-size:12px">Try a different search term or mode</div>
      </div>
    </template>

    <!-- Landing tips -->
    <div v-else style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px">
      <div v-for="tip in tips" :key="tip.title" style="background:#1e293b;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:18px">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
          <div style="width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.2)">
            <i :class="`fas ${tip.icon}`" :style="`color:${tip.color};font-size:15px`" />
          </div>
          <span style="color:#e2e8f0;font-weight:600;font-size:14px">{{ tip.title }}</span>
        </div>
        <p style="color:#64748b;font-size:12px;margin:0 0 10px">{{ tip.desc }}</p>
        <div style="background:#0f172a;border-radius:6px;padding:6px 10px;font-family:monospace;font-size:12px;color:#94a3b8">{{ tip.example }}</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useDevicesStore } from '@/stores/devices'
import { useToastStore } from '@/stores/toast'
import { searchApi } from '@/api'

const devicesStore = useDevicesStore()
const toast = useToastStore()

const query = ref('')
const mode = ref('any')
const selectedDeviceId = ref('')
const results = ref([])
const searched = ref(false)
const searching = ref(false)
const inputRef = ref(null)

const modes = [
  { key:'any',  icon:'fa-asterisk' },
  { key:'name', icon:'fa-id-badge' },
  { key:'ip',   icon:'fa-network-wired' },
  { key:'port', icon:'fa-plug' },
]

const tips = [
  { icon:'fa-network-wired', color:'#3b82f6', title:'IP Search', desc:'Find rules matching a specific source or destination IP address.', example:'192.168.1.10' },
  { icon:'fa-plug',          color:'#8b5cf6', title:'Port Search', desc:'Find rules that allow or deny a specific port number.', example:'443' },
  { icon:'fa-id-badge',      color:'#06b6d4', title:'Name Search', desc:'Search by rule name — partial matches are supported.', example:'Allow-HTTP' },
  { icon:'fa-asterisk',      color:'#10b981', title:'Any Search', desc:'Search across name, IP, and port simultaneously.', example:'10.0.0.1 or 80' },
]

async function doSearch() {
  if (!query.value.trim()) return
  searching.value = true
  try {
    const res = await searchApi.search({ q: query.value, mode: mode.value, device_id: selectedDeviceId.value || undefined })
    results.value = res.data || []
    searched.value = true
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Search failed')
  } finally {
    searching.value = false
  }
}

function actionBg(a) {
  if (!a) return 'rgba(100,116,139,.15)'
  const v = a.toUpperCase()
  if (v==='ALLOW'||v==='PASS') return 'rgba(34,197,94,.15)'
  if (v==='DENY'||v==='DROP') return 'rgba(239,68,68,.15)'
  return 'rgba(100,116,139,.15)'
}

function actionColor(a) {
  if (!a) return '#94a3b8'
  const v = a.toUpperCase()
  if (v==='ALLOW'||v==='PASS') return '#22c55e'
  if (v==='DENY'||v==='DROP') return '#ef4444'
  return '#94a3b8'
}

onMounted(async () => {
  await devicesStore.fetchDevices()
  // Ctrl+K focus
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault()
      inputRef.value?.focus()
    }
  })
})
</script>
