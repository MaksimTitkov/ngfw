<template>
  <div class="app-topbar">
    <span class="topbar-title">
      <i class="fas fa-gauge-high" style="color:#3b82f6;margin-right:6px" />
      {{ selectedDevice ? selectedDevice.name : 'Dashboard' }}
    </span>
    <div class="topbar-sep" />
    <button v-if="selectedDevice" class="btn-top" @click="selectedDevice = null">
      <i class="fas fa-arrow-left" /> All Devices
    </button>
    <router-link to="/analyzer" class="btn-top"><i class="fas fa-magnifying-glass-chart" /> Analyzer</router-link>
  </div>

  <div class="app-content" style="padding:20px">
    <div v-if="loading" class="empty-state"><div class="spinner-ring" style="margin:0 auto 12px" /></div>

    <!-- GLOBAL VIEW -->
    <template v-else-if="!selectedDevice">
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:14px;margin-bottom:28px">
        <div class="dash-card" style="border-left:3px solid #10b981">
          <div class="dash-card-icon" style="background:rgba(16,185,129,.15)"><i class="fas fa-network-wired" style="color:#10b981" /></div>
          <div class="dash-card-body"><div class="dash-card-val">{{ devicesStore.devices.length }}</div><div class="dash-card-lbl">Devices</div></div>
        </div>
        <div class="dash-card" style="border-left:3px solid #f43f5e">
          <div class="dash-card-icon" style="background:rgba(244,63,94,.15)"><i class="fas fa-clock-rotate-left" style="color:#f43f5e" /></div>
          <div class="dash-card-body"><div class="dash-card-val">{{ changelog.length }}</div><div class="dash-card-lbl">Recent Changes</div></div>
        </div>
      </div>

      <div style="margin-bottom:28px">
        <div class="dash-section-title"><i class="fas fa-network-wired" style="color:#3b82f6;margin-right:6px" />Devices</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px">
          <div v-for="d in devicesStore.devices" :key="d.id" class="dash-device-card" @click="selectDevice(d)">
            <div style="width:34px;height:34px;border-radius:8px;background:rgba(59,130,246,.12);display:flex;align-items:center;justify-content:center;flex-shrink:0">
              <i class="fas fa-server" style="color:#3b82f6;font-size:13px" />
            </div>
            <div style="min-width:0;flex:1">
              <div style="color:#e2e8f0;font-weight:600;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{{ d.name }}</div>
              <div style="color:#475569;font-size:10px;margin-top:1px">{{ d.id.slice(0,8) }}…</div>
            </div>
            <i class="fas fa-chevron-right" style="color:#334155;font-size:10px;flex-shrink:0" />
          </div>
        </div>
      </div>

      <div>
        <div class="dash-section-title">
          <i class="fas fa-clock-rotate-left" style="color:#f43f5e;margin-right:6px" />Recent Changes
          <router-link to="/changelog" style="margin-left:auto;color:#3b82f6;font-size:11px;font-weight:400;text-decoration:none">View All</router-link>
        </div>
        <ChangelogTable :entries="changelog" dark :show-device="true" />
      </div>
    </template>

    <!-- DEVICE VIEW -->
    <template v-else>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:14px;margin-bottom:28px">
        <div class="dash-card" style="border-left:3px solid #3b82f6">
          <div class="dash-card-icon" style="background:rgba(59,130,246,.15)"><i class="fas fa-layer-group" style="color:#3b82f6" /></div>
          <div class="dash-card-body"><div class="dash-card-val">{{ stats.sec_total ?? '—' }}</div><div class="dash-card-lbl">Security Rules</div></div>
        </div>
        <div class="dash-card" :style="`border-left:3px solid ${(stats.sec_modified||0) > 0 ? '#f59e0b' : '#22c55e'}`">
          <div class="dash-card-icon" :style="`background:rgba(${(stats.sec_modified||0) > 0 ? '245,158,11' : '34,197,94'},.15)`">
            <i :class="`fas fa-${(stats.sec_modified||0) > 0 ? 'triangle-exclamation' : 'check-circle'}`" :style="`color:${(stats.sec_modified||0) > 0 ? '#f59e0b' : '#22c55e'}`" />
          </div>
          <div class="dash-card-body"><div class="dash-card-val">{{ stats.sec_modified ?? 0 }}</div><div class="dash-card-lbl">Sec Modified</div></div>
        </div>
        <div class="dash-card" style="border-left:3px solid #8b5cf6">
          <div class="dash-card-icon" style="background:rgba(139,92,246,.15)"><i class="fas fa-arrows-left-right" style="color:#8b5cf6" /></div>
          <div class="dash-card-body"><div class="dash-card-val">{{ stats.nat_total ?? '—' }}</div><div class="dash-card-lbl">NAT Rules</div></div>
        </div>
        <div class="dash-card" style="border-left:3px solid #06b6d4">
          <div class="dash-card-icon" style="background:rgba(6,182,212,.15)"><i class="fas fa-cubes" style="color:#06b6d4" /></div>
          <div class="dash-card-body"><div class="dash-card-val">{{ stats.objects ?? '—' }}</div><div class="dash-card-lbl">Objects</div></div>
        </div>
        <div v-if="analysis" class="dash-card" :style="`border-left:3px solid ${analysis.total_issues > 0 ? '#ef4444' : '#22c55e'}`">
          <div class="dash-card-icon" :style="`background:rgba(${analysis.total_issues > 0 ? '239,68,68' : '34,197,94'},.15)`">
            <i :class="`fas fa-${analysis.total_issues > 0 ? 'bug' : 'shield-halved'}`" :style="`color:${analysis.total_issues > 0 ? '#ef4444' : '#22c55e'}`" />
          </div>
          <div class="dash-card-body"><div class="dash-card-val">{{ analysis.total_issues }}</div><div class="dash-card-lbl">Issues</div></div>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
        <div style="display:flex;flex-direction:column;gap:20px">
          <!-- Analyzer results -->
          <div v-if="analysis">
            <div class="dash-section-title">
              <i class="fas fa-magnifying-glass-chart" style="color:#a78bfa;margin-right:6px" />Analyzer
              <span style="margin-left:auto;font-size:10px;color:#475569;font-weight:400">as of {{ analysis.analyzed_at }}</span>
            </div>
            <template v-if="analysis.total_issues > 0">
              <div style="display:flex;flex-direction:column;gap:8px">
                <AnalyzerRow v-if="analysis.disabled?.length" icon="fa-toggle-off" color="#64748b" label="Disabled rules" :count="analysis.disabled.length" />
                <AnalyzerRow v-if="analysis.too_broad?.length" icon="fa-expand" color="#f59e0b" label="Too broad" :count="analysis.too_broad.length" />
                <AnalyzerRow v-if="analysis.shadowed?.length" icon="fa-eye-slash" color="#ef4444" label="Shadowed" :count="analysis.shadowed.length" />
                <AnalyzerRow v-if="analysis.redundant?.length" icon="fa-copy" color="#8b5cf6" label="Redundant" :count="analysis.redundant.length" />
              </div>
              <router-link to="/analyzer" style="display:block;margin-top:8px;text-align:center;font-size:11px;color:#60a5fa;text-decoration:none;padding:7px;background:rgba(59,130,246,.07);border:1px solid rgba(59,130,246,.15);border-radius:7px">
                <i class="fas fa-arrow-right" style="font-size:10px" /> Open Analyzer
              </router-link>
            </template>
            <div v-else style="padding:20px;background:#1e293b;border:1px solid rgba(34,197,94,.15);border-radius:10px;text-align:center">
              <i class="fas fa-shield-halved" style="font-size:24px;color:#22c55e;display:block;margin-bottom:8px" />
              <div style="color:#22c55e;font-weight:600;font-size:13px">No Issues Found</div>
            </div>
          </div>

          <!-- Quick links -->
          <div>
            <div class="dash-section-title"><i class="fas fa-bolt" style="color:#f59e0b;margin-right:6px" />Quick Navigation</div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
              <router-link v-for="lnk in quickLinks" :key="lnk.to" :to="lnk.to" class="dash-quick-link">
                <i :class="`fas ${lnk.icon}`" :style="`color:${lnk.color};width:14px;text-align:center`" />
                <span style="color:#94a3b8;font-size:11px;font-weight:600">{{ lnk.label }}</span>
              </router-link>
            </div>
          </div>
        </div>

        <div style="display:flex;flex-direction:column;gap:20px">
          <div>
            <div class="dash-section-title">
              <i class="fas fa-clock-rotate-left" style="color:#f43f5e;margin-right:6px" />Recent Changes
              <router-link to="/changelog" style="margin-left:auto;color:#3b82f6;font-size:11px;font-weight:400;text-decoration:none">View All</router-link>
            </div>
            <ChangelogTable :entries="changelog" dark />
          </div>

          <div v-if="modifiedRules.length">
            <div class="dash-section-title"><i class="fas fa-triangle-exclamation" style="color:#f59e0b;margin-right:6px" />Modified on Device</div>
            <div style="background:#1e293b;border:1px solid rgba(245,158,11,.2);border-radius:10px;overflow:hidden">
              <table style="width:100%;border-collapse:collapse;font-size:12px">
                <thead><tr style="background:rgba(245,158,11,.06)">
                  <th style="padding:7px 10px;color:#94a3b8;font-weight:600;text-align:left">Rule</th>
                  <th style="padding:7px 10px;color:#94a3b8;font-weight:600;text-align:left;white-space:nowrap">Modified</th>
                </tr></thead>
                <tbody>
                  <tr v-for="r in modifiedRules.slice(0,10)" :key="r.id" style="border-top:1px solid rgba(255,255,255,.04)">
                    <td style="padding:6px 10px;color:#fbbf24;font-weight:500;font-size:12px">{{ r.name }}</td>
                    <td style="padding:6px 10px;color:#64748b;font-size:11px">{{ r.modified_at?.slice(0,16) || '—' }}</td>
                  </tr>
                </tbody>
              </table>
              <div v-if="modifiedRules.length > 10" style="padding:7px 10px;text-align:center;color:#64748b;font-size:11px;border-top:1px solid rgba(255,255,255,.04)">
                … and {{ modifiedRules.length - 10 }} more
              </div>
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, watch, onMounted } from 'vue'
import { useDevicesStore } from '@/stores/devices'
import { useToastStore } from '@/stores/toast'
import { changelogApi, analyzerApi, diffApi } from '@/api'
import api from '@/api'
import ChangelogTable from '@/components/ChangelogTable.vue'
import AnalyzerRow from '@/components/AnalyzerRow.vue'

const devicesStore = useDevicesStore()
const toast = useToastStore()

const loading = ref(false)
const selectedDevice = ref(null)
const changelog = ref([])
const stats = ref({})
const analysis = ref(null)
const modifiedRules = ref([])

const quickLinks = [
  { to: '/', icon: 'fa-layer-group', color: '#3b82f6', label: 'Security' },
  { to: '/nat', icon: 'fa-arrows-left-right', color: '#8b5cf6', label: 'NAT' },
  { to: '/objects', icon: 'fa-cubes', color: '#06b6d4', label: 'Objects' },
  { to: '/diff', icon: 'fa-code-compare', color: '#34d399', label: 'Diff' },
]

async function loadGlobal() {
  loading.value = true
  try {
    const res = await changelogApi.query({ limit: 20 })
    changelog.value = res.data?.items || res.data || []
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Failed to load dashboard')
  } finally {
    loading.value = false
  }
}

async function loadDevice(deviceId) {
  loading.value = true
  analysis.value = null
  modifiedRules.value = []
  stats.value = {}
  try {
    const [clRes, analyzerRes, modRes] = await Promise.allSettled([
      changelogApi.query({ device_id: deviceId, limit: 20 }),
      analyzerApi.cached({ device_id: deviceId }),
      diffApi.modified({ device_id: deviceId }),
    ])
    changelog.value = clRes.value?.data?.items || clRes.value?.data || []
    analysis.value = analyzerRes.value?.data || null
    modifiedRules.value = modRes.value?.data || []
  } finally {
    loading.value = false
  }
}

function selectDevice(d) {
  selectedDevice.value = d
}

watch(selectedDevice, (d) => {
  if (d) loadDevice(d.id)
  else loadGlobal()
})

onMounted(async () => {
  await devicesStore.fetchDevices()
  loadGlobal()
})
</script>

<style scoped>
.dash-card { display:flex;align-items:center;gap:12px;background:#1e293b;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:14px 16px }
.dash-card-icon { width:40px;height:40px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0 }
.dash-card-val { font-size:24px;font-weight:700;color:#e2e8f0;line-height:1 }
.dash-card-lbl { font-size:11px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:2px }
.dash-section-title { display:flex;align-items:center;color:#94a3b8;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px }
.dash-device-card { display:flex;align-items:center;gap:10px;padding:12px 16px;border-radius:10px;background:#1e293b;border:1px solid rgba(255,255,255,.07);cursor:pointer;transition:.15s }
.dash-device-card:hover { border-color:rgba(59,130,246,.4) }
.dash-quick-link { display:flex;align-items:center;gap:8px;padding:10px 12px;border-radius:8px;background:#1e293b;border:1px solid rgba(255,255,255,.07);text-decoration:none;transition:.15s }
.dash-quick-link:hover { border-color:rgba(59,130,246,.3) }
</style>
