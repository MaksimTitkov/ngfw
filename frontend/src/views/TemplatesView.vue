<template>
  <div class="app-topbar">
    <span class="topbar-title"><i class="fas fa-layer-group" style="color:#f59e0b;margin-right:6px" />Rule Templates</span>
    <div class="topbar-sep" />
    <span style="font-size:12px;color:#64748b">{{ templates.length }} templates</span>
    <div style="flex:1" />
  </div>

  <div class="app-content" style="padding:20px">
    <!-- Bulk bar -->
    <div v-if="selected.size > 0" style="display:flex;align-items:center;gap:10px;margin-bottom:14px;background:#1e293b;border-radius:8px;padding:10px 16px">
      <span style="color:#fff;font-size:13px">{{ selected.size }} selected</span>
      <button class="btn-bulk red" @click="bulkDelete"><i class="fas fa-trash me-1" />Delete</button>
      <button class="btn-bulk light" @click="selected.clear();selected=new Set(selected)"><i class="fas fa-xmark" /></button>
    </div>

    <div v-if="loading" class="empty-state"><div class="spinner-ring" style="margin:0 auto 12px" /></div>

    <div v-else-if="!templates.length" style="background:#1e293b;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:60px 20px;text-align:center;color:#475569">
      <i class="fas fa-layer-group" style="font-size:40px;opacity:.2;display:block;margin-bottom:14px" />
      <div style="font-size:15px;font-weight:600;margin-bottom:8px;color:#64748b">No Templates</div>
      <div style="font-size:13px">Save a rule as template from the rule editor to see it here.</div>
    </div>

    <div v-else style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px">
      <div v-for="t in templates" :key="t.id" class="tmpl-card">
        <div style="display:flex;align-items:flex-start;gap:10px">
          <input type="checkbox" class="form-check-input" :checked="selected.has(t.id)" @change="toggleSelect(t.id)" style="margin-top:3px;flex-shrink:0" />
          <div style="flex:1;min-width:0">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
              <span style="font-weight:700;font-size:14px;color:#e2e8f0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ t.name }}</span>
              <span :style="`flex-shrink:0;padding:1px 8px;border-radius:20px;font-size:10px;font-weight:700;background:${actionBg(t.action)};color:${actionColor(t.action)}`">
                {{ t.action || '?' }}
              </span>
            </div>
            <div v-if="t.description" style="font-size:12px;color:#64748b;margin-bottom:8px">{{ t.description }}</div>
            <div style="font-size:11px;color:#334155">
              <i class="fas fa-user" style="margin-right:4px" />{{ t.created_by || 'Unknown' }}
              &nbsp;·&nbsp;
              <i class="fas fa-clock" style="margin-right:4px" />{{ fmtDt(t.created_at) }}
            </div>
          </div>
        </div>
        <div style="margin-top:12px;display:flex;gap:8px">
          <button class="btn btn-sm" style="flex:1;background:rgba(59,130,246,.15);color:#60a5fa;border:1px solid rgba(59,130,246,.2);font-size:12px"
                  @click="openApplyModal(t)">
            <i class="fas fa-play me-1" />Apply to Folder
          </button>
          <button class="btn btn-sm" style="background:rgba(239,68,68,.1);color:#f87171;border:1px solid rgba(239,68,68,.2);font-size:12px"
                  @click="deleteOne(t.id)">
            <i class="fas fa-trash" />
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- Apply Template Modal -->
  <div v-if="showApplyModal" class="modal-backdrop" @click.self="showApplyModal=false">
    <div class="modal-box" style="max-width:440px">
      <div class="modal-header">
        <h5 class="modal-title"><i class="fas fa-play me-2" style="color:#3b82f6" />Apply Template</h5>
        <button class="btn-close" @click="showApplyModal=false" />
      </div>
      <div class="modal-body">
        <p style="color:#94a3b8;font-size:13px">Apply <b style="color:#e2e8f0">{{ applyTemplate?.name }}</b> to a folder:</p>
        <div class="mb-3">
          <label class="form-label-sm">Device</label>
          <select v-model="applyDevice" class="form-select" @change="loadFolders">
            <option value="">Select device…</option>
            <option v-for="d in devicesStore.devices" :key="d.id" :value="d.id">{{ d.name }}</option>
          </select>
        </div>
        <div class="mb-3">
          <label class="form-label-sm">Folder</label>
          <select v-model="applyFolder" class="form-select" :disabled="!applyFolders.length">
            <option value="">Select folder…</option>
            <option v-for="f in applyFolders" :key="f.id" :value="f.id">{{ f.name }}</option>
          </select>
        </div>
        <div v-if="applying" style="display:flex;align-items:center;gap:8px;font-size:12px;color:#94a3b8">
          <div class="spinner-ring" style="width:18px;height:18px;border-width:2px" /> Applying…
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-light" @click="showApplyModal=false">Cancel</button>
        <button class="btn btn-primary fw-bold" @click="submitApply" :disabled="applying||!applyFolder">
          <i class="fas fa-play me-1" />Apply
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useDevicesStore } from '@/stores/devices'
import { useToastStore } from '@/stores/toast'
import { templatesApi, rulesApi } from '@/api'

const devicesStore = useDevicesStore()
const toast = useToastStore()
const router = useRouter()

const templates = ref([])
const loading = ref(false)
const selected = ref(new Set())

const showApplyModal = ref(false)
const applyTemplate = ref(null)
const applyDevice = ref('')
const applyFolder = ref('')
const applyFolders = ref([])
const applying = ref(false)

async function loadTemplates() {
  loading.value = true
  try {
    const res = await templatesApi.save // just load list via profiles or dedicated endpoint
    // The API returns templates via GET /api/v1/profiles/list or similar
    const r = await fetch('/api/v1/templates/list').catch(() => null)
    if (r?.ok) { templates.value = await r.json() }
  } catch { /**/ } finally { loading.value = false }
}

function toggleSelect(id) {
  const s = new Set(selected.value)
  s.has(id) ? s.delete(id) : s.add(id)
  selected.value = s
}

async function bulkDelete() {
  if (!confirm(`Delete ${selected.value.size} template(s)?`)) return
  try {
    await templatesApi.delete({ template_ids: [...selected.value] })
    toast.success('Deleted'); selected.value = new Set(); await loadTemplates()
  } catch (e) { toast.error(e.response?.data?.detail || 'Delete failed') }
}

async function deleteOne(id) {
  if (!confirm('Delete this template?')) return
  try { await templatesApi.delete({ template_ids: [id] }); toast.success('Deleted'); await loadTemplates() }
  catch (e) { toast.error(e.response?.data?.detail || 'Delete failed') }
}

function openApplyModal(t) {
  applyTemplate.value = t; applyDevice.value = ''; applyFolder.value = ''; applyFolders.value = []
  showApplyModal.value = true
}

async function loadFolders() {
  if (!applyDevice.value) { applyFolders.value = []; return }
  try {
    const res = await rulesApi.getFolderTree({ device_id: applyDevice.value })
    const out = []
    const walk = (nodes) => { for (const n of (nodes||[])) { if (n.rules!==undefined) out.push(n); walk(n.children) } }
    walk(Array.isArray(res.data) ? res.data : [res.data])
    applyFolders.value = out
  } catch { applyFolders.value = [] }
}

async function submitApply() {
  if (!applyFolder.value) return
  applying.value = true
  try {
    await templatesApi.apply({ template_id: applyTemplate.value.id, folder_id: applyFolder.value })
    toast.success('Template applied'); showApplyModal.value = false
    router.push(`/?folder_id=${applyFolder.value}`)
  } catch (e) { toast.error(e.response?.data?.detail || 'Apply failed') }
  finally { applying.value = false }
}

function fmtDt(dt) {
  if (!dt) return ''
  return new Date(dt).toLocaleDateString('ru-RU', { day:'2-digit', month:'2-digit', year:'2-digit' })
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
  await loadTemplates()
})
</script>

<style scoped>
.tmpl-card { background:#1e293b;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:16px;transition:.15s }
.tmpl-card:hover { border-color:rgba(59,130,246,.25) }
.modal-backdrop { position:fixed;inset:0;background:rgba(15,23,42,.5);z-index:1050;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(2px) }
.modal-box { background:#fff;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.2);width:90%;display:flex;flex-direction:column;max-height:90vh }
.btn-bulk { padding:5px 14px;border-radius:20px;border:none;font-size:12px;font-weight:600;cursor:pointer }
.btn-bulk.red { background:var(--danger);color:#fff }
.btn-bulk.light { background:rgba(255,255,255,.15);color:#fff }
</style>
