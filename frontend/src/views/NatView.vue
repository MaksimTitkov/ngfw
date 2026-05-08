<template>
  <div class="app-topbar">
    <span class="topbar-title"><i class="fas fa-arrows-left-right" style="color:#3b82f6;margin-right:6px" />NAT Policy</span>
    <div class="topbar-sep" />
    <select v-model="selectedDeviceId" class="form-select" style="width:200px;height:32px;font-size:12px;padding:0 8px" @change="loadTree">
      <option v-for="d in devicesStore.devices" :key="d.id" :value="d.id">{{ d.name }}</option>
    </select>
    <div class="topbar-sep" />
    <button class="btn-top" @click="doSync" :disabled="syncing"><i class="fas fa-rotate" :class="{'fa-spin':syncing}" /> Sync</button>
    <button v-if="!auth.isReadOnly" class="btn-top success" @click="doDeploy" :disabled="deploying"><i class="fas fa-upload" /> Deploy</button>
    <div style="margin-left:auto;display:flex;gap:8px">
      <template v-if="!auth.isReadOnly">
        <button class="btn-top" @click="showFolderModal=true"><i class="fas fa-folder-plus" /> New Folder</button>
        <button class="btn-top primary" @click="openCreate(null)"><i class="fas fa-plus" /> Add Rule</button>
      </template>
    </div>
  </div>

  <div style="display:flex;flex:1;overflow:hidden">
    <!-- Sidebar folder tree -->
    <div style="width:200px;border-right:1px solid var(--border);background:var(--surface);overflow-y:auto;padding:8px 0;flex-shrink:0">
      <div class="sidebar-section-label">NAT Folders</div>
      <div
        v-for="folder in allFolders" :key="folder.id"
        class="folder-link" :class="{active: activeFolderId===folder.id}"
        @click="activeFolderId=folder.id"
      >
        <i class="fas fa-folder" style="font-size:11px" />
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ folder.name }}</span>
        <span class="folder-count">{{ folder.rules?.length ?? 0 }}</span>
      </div>
    </div>

    <!-- Main content -->
    <div class="app-content" style="flex:1">
      <div v-if="loading" class="empty-state"><div class="spinner-ring" style="margin:0 auto 12px" /></div>
      <div v-else-if="!allFolders.length" class="empty-state">
        <i class="fas fa-arrows-left-right" /><div style="margin-top:8px">No NAT rules. Sync a device or create a folder.</div>
      </div>
      <template v-else>
        <div v-for="folder in visibleFolders" :key="folder.id" class="folder-card">
          <div class="folder-card-header">
            <span class="folder-card-title">
              <i class="fas fa-folder-open" style="color:#3b82f6" />{{ folder.name }}
              <span v-if="folder.section" class="section-badge" :class="folder.section">{{ folder.section.toUpperCase() }}</span>
            </span>
            <span style="margin-left:auto;font-size:11px;color:var(--text-muted)">{{ folder.rules?.length||0 }} rules</span>
            <button class="btn-top" style="padding:4px 10px" @click="openCreate(folder.id)"><i class="fas fa-plus" /> Rule</button>
          </div>
          <div class="table-scroll">
            <table class="rules-table">
              <thead><tr>
                <th style="width:28px"></th><th style="width:28px"></th><th style="width:32px">#</th>
                <th>Name</th><th>Src Zone</th><th>Source</th><th>Dst Zone</th>
                <th>Destination</th><th>Service</th><th>SNAT</th><th>DNAT</th>
                <th style="width:50px;text-align:center">On</th><th style="width:40px"></th>
              </tr></thead>
              <VueDraggable tag="tbody" v-model="folder.rules" handle=".drag-handle" :animation="150" ghost-class="sortable-ghost" @end="()=>reorderRules(folder)">
                <tr v-for="(r,idx) in folder.rules" :key="r.id"
                    :style="r.is_modified?'background:#fffbeb;border-left:3px solid #f59e0b':''"
                    @dblclick="openEdit(r,folder.id)">
                  <td><i class="fas fa-grip-vertical drag-handle" /></td>
                  <td><input type="checkbox" style="cursor:pointer" /></td>
                  <td style="color:#94a3b8;font-size:11px">{{ idx+1 }}</td>
                  <td>
                    <div class="rule-name">{{ r.name }}
                      <span v-if="r.is_modified" title="Modified on device" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#f59e0b;margin-left:5px;vertical-align:middle" />
                    </div>
                  </td>
                  <td><span v-if="r.src_zone==='Any'" class="rule-any">Any</span><span v-else v-html="r.src_zone" /></td>
                  <td><span v-if="r.src_net==='Any'" class="rule-any">Any</span><span v-else style="font-size:12px" v-html="r.src_net" /></td>
                  <td><span v-if="r.dst_zone==='Any'" class="rule-any">Any</span><span v-else v-html="r.dst_zone" /></td>
                  <td><span v-if="r.dst_net==='Any'" class="rule-any">Any</span><span v-else style="font-size:12px" v-html="r.dst_net" /></td>
                  <td><span v-if="r.service==='Any'" class="rule-any">Any</span><span v-else style="font-size:12px" v-html="r.service" /></td>
                  <td>
                    <span v-if="!r.snat_type||r.snat_type==='None'" class="rule-any">None</span>
                    <span v-else class="action-badge" style="background:#dbeafe;color:#1d4ed8;font-size:10px">{{ snatLabel(r.snat_type) }}</span>
                  </td>
                  <td>
                    <span v-if="!r.dnat_type||r.dnat_type==='None'" class="rule-any">None</span>
                    <span v-else class="action-badge" style="background:#fce7f3;color:#be185d;font-size:10px">{{ dnatLabel(r.dnat_type) }}</span>
                  </td>
                  <td style="text-align:center">
                    <div class="form-check form-switch d-flex justify-content-center mb-0">
                      <input class="form-check-input" type="checkbox" role="switch" :checked="r.enabled" @change="toggleRule(r,$event.target.checked)" />
                    </div>
                  </td>
                  <td>
                    <div style="display:flex;gap:2px;justify-content:flex-end">
                      <button class="row-btn" @click.stop="openEdit(r,folder.id)" title="Edit"><i class="fas fa-pen" /></button>
                      <button class="row-btn danger" @click.stop="deleteRule(r.id)" title="Delete"><i class="fas fa-trash" /></button>
                    </div>
                  </td>
                </tr>
                <tr v-if="!folder.rules?.length">
                  <td colspan="13" style="text-align:center;padding:20px;color:#94a3b8;font-style:italic;font-size:12px">Empty folder — click "+ Rule" to add NAT rules</td>
                </tr>
              </VueDraggable>
            </table>
          </div>
        </div>
      </template>
    </div>
  </div>

  <!-- NAT Rule Modal -->
  <div v-if="showModal" class="modal-backdrop" @click.self="showModal=false">
    <div class="modal-box modal-xl">
      <div class="modal-header">
        <h5 class="modal-title">{{ editRule?'Edit NAT Rule':'New NAT Rule' }}</h5>
        <button class="btn-close" @click="showModal=false" />
      </div>
      <div class="modal-body" style="max-height:75vh;overflow-y:auto">
        <div class="row g-3 mb-3">
          <div class="col-md-8">
            <label class="form-label-sm">Rule Name <span style="color:#ef4444">*</span></label>
            <input v-model="form.name" class="form-control" placeholder="e.g. SNAT-LAN-to-WAN" />
          </div>
          <div class="col-md-2">
            <label class="form-label-sm">Enabled</label>
            <div class="form-check form-switch mt-1"><input class="form-check-input" type="checkbox" v-model="form.enabled" style="width:2.2em;height:1.1em" /></div>
          </div>
          <div class="col-md-2">
            <label class="form-label-sm">Description</label>
            <input v-model="form.description" class="form-control" placeholder="Optional" style="font-size:12px" />
          </div>
        </div>
        <hr style="margin:4px 0 14px;border-color:#f1f5f9" />
        <div class="rule-form-section"><i class="fas fa-map-location-dot me-1" />Match — Zones</div>
        <div class="row g-3 mb-3">
          <div class="col-md-6"><label class="form-label-sm">Source Zone</label><ObjectPicker v-model="form.src_zones" :items="zoneItems" placeholder="Any zone…" tag-class="zone-t" /></div>
          <div class="col-md-6"><label class="form-label-sm">Destination Zone</label><ObjectPicker v-model="form.dst_zones" :items="zoneItems" placeholder="Any zone…" tag-class="zone-t" /></div>
        </div>
        <div class="rule-form-section"><i class="fas fa-network-wired me-1" />Match — Addresses & Service</div>
        <div class="row g-3 mb-3">
          <div class="col-md-4"><label class="form-label-sm">Source Address</label><ObjectPicker v-model="form.src_ips" :items="netItems" placeholder="Any source…" /></div>
          <div class="col-md-4"><label class="form-label-sm">Destination Address</label><ObjectPicker v-model="form.dst_ips" :items="netItems" placeholder="Any destination…" /></div>
          <div class="col-md-4"><label class="form-label-sm">Service</label><ObjectPicker v-model="form.services" :items="serviceItems" placeholder="Any service…" tag-class="svc-t" /></div>
        </div>
        <hr style="margin:4px 0 14px;border-color:#f1f5f9" />
        <div class="rule-form-section"><i class="fas fa-arrow-right-arrow-left me-1" />Source NAT (SNAT)</div>
        <div class="row g-3 mb-3">
          <div class="col-md-4">
            <label class="form-label-sm">SNAT Type</label>
            <select v-model="form.snat_type" class="form-select" style="font-size:12px">
              <option value="NAT_SOURCE_TRANSLATION_TYPE_NONE">None (No SNAT)</option>
              <option value="NAT_SOURCE_TRANSLATION_TYPE_DYNAMIC_IP_PORT">PAT (Dynamic IP+Port)</option>
              <option value="NAT_SOURCE_TRANSLATION_TYPE_STATIC_IP">Static IP</option>
              <option value="NAT_SOURCE_TRANSLATION_TYPE_STATIC_IP_PORT">Static IP+Port</option>
            </select>
          </div>
          <div v-if="form.snat_type!=='NAT_SOURCE_TRANSLATION_TYPE_NONE'" class="col-md-4">
            <label class="form-label-sm">Source Address Type</label>
            <select v-model="form.src_addr_type" class="form-select" style="font-size:12px">
              <option value="NAT_SOURCE_TRANSLATION_ADDRESS_TYPE_NONE">None</option>
              <option value="NAT_SOURCE_TRANSLATION_ADDRESS_TYPE_INTERFACE_ADDRESS">Interface Address</option>
              <option value="NAT_SOURCE_TRANSLATION_ADDRESS_TYPE_ADDRESS_POOL">Address Pool</option>
            </select>
          </div>
          <div v-if="form.src_addr_type==='NAT_SOURCE_TRANSLATION_ADDRESS_TYPE_ADDRESS_POOL'" class="col-md-4">
            <label class="form-label-sm">Translated Source Address</label>
            <ObjectPicker v-model="form.src_translated" :items="netItems" placeholder="Select pool…" />
          </div>
        </div>
        <div class="rule-form-section"><i class="fas fa-arrow-right me-1" />Destination NAT (DNAT)</div>
        <div class="row g-3 mb-3">
          <div class="col-md-4">
            <label class="form-label-sm">DNAT Type</label>
            <select v-model="form.dnat_type" class="form-select" style="font-size:12px">
              <option value="NAT_DESTINATION_TRANSLATION_TYPE_NONE">None (No DNAT)</option>
              <option value="NAT_DESTINATION_TRANSLATION_TYPE_ADDRESS_POOL">DNAT (Address Pool)</option>
            </select>
          </div>
          <div v-if="form.dnat_type!=='NAT_DESTINATION_TRANSLATION_TYPE_NONE'" class="col-md-4">
            <label class="form-label-sm">Translated Destination Address</label>
            <ObjectPicker v-model="form.dst_translated" :items="netItems" placeholder="Select pool…" />
          </div>
          <div v-if="form.dnat_type!=='NAT_DESTINATION_TRANSLATION_TYPE_NONE'" class="col-md-4">
            <label class="form-label-sm">Translated Destination Port</label>
            <input v-model.number="form.dst_translated_port" type="number" class="form-control" placeholder="e.g. 8080" min="1" max="65535" style="font-size:12px" />
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <div v-if="saving" style="display:flex;align-items:center;gap:8px;font-size:12px;color:#64748b"><div class="spinner-ring" style="width:18px;height:18px;border-width:2px" /> Saving…</div>
        <button class="btn btn-light" @click="showModal=false">Cancel</button>
        <button class="btn btn-primary fw-bold" @click="submitNat" :disabled="saving"><i class="fas fa-save me-1" />{{ editRule?'Save Changes':'Create Rule' }}</button>
      </div>
    </div>
  </div>

  <!-- Create Folder Modal -->
  <div v-if="showFolderModal" class="modal-backdrop" @click.self="showFolderModal=false">
    <div class="modal-box" style="max-width:380px">
      <div class="modal-header"><h5 class="modal-title"><i class="fas fa-folder-plus me-2 text-primary" />New NAT Folder</h5><button class="btn-close" @click="showFolderModal=false" /></div>
      <div class="modal-body">
        <div class="mb-3"><label class="form-label-sm">Folder Name</label><input v-model="newFolderName" class="form-control" placeholder="e.g. VLAN100 NAT" autofocus /></div>
        <div><label class="form-label-sm">Section</label>
          <div class="action-group">
            <button v-for="s in ['pre','default','post']" :key="s" class="action-btn" :class="newFolderSection===s?'active allow':''" @click="newFolderSection=s">{{ s.toUpperCase() }}</button>
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-light btn-sm" @click="showFolderModal=false">Cancel</button>
        <button class="btn btn-primary btn-sm fw-bold" @click="createFolder">Create</button>
      </div>
    </div>
  </div>

  <div v-if="syncing||deploying" class="loading-overlay">
    <div class="spinner-ring" /><div style="font-size:14px;font-weight:600">{{ syncing?'Syncing…':'Deploying…' }}</div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { VueDraggable } from 'vue-draggable-plus'
import axios from 'axios'
import { useDevicesStore } from '@/stores/devices'
import { useToastStore } from '@/stores/toast'
import { useAuthStore } from '@/stores/auth'
import { natApi, objectsApi, deviceApi } from '@/api'
import ObjectPicker from '@/components/ObjectPicker.vue'

const devicesStore = useDevicesStore()
const toast = useToastStore()
const auth = useAuthStore()

const selectedDeviceId = ref(null)
const tree = ref([])
const loading = ref(false)
const syncing = ref(false)
const deploying = ref(false)
const activeFolderId = ref(null)
const showModal = ref(false)
const showFolderModal = ref(false)
const editRule = ref(null)
const saving = ref(false)
const newFolderName = ref('')
const newFolderSection = ref('pre')

const zoneItems = ref([])
const netItems = ref([])
const serviceItems = ref([])

const emptyForm = () => ({
  name:'', enabled:true, description:'', folder_id:null,
  src_zones:[], dst_zones:[], src_ips:[], dst_ips:[], services:[],
  snat_type:'NAT_SOURCE_TRANSLATION_TYPE_NONE',
  src_addr_type:'NAT_SOURCE_TRANSLATION_ADDRESS_TYPE_NONE',
  src_translated:[],
  dnat_type:'NAT_DESTINATION_TRANSLATION_TYPE_NONE',
  dst_translated:[], dst_translated_port:null,
})
const form = ref(emptyForm())

const allFolders = computed(() => {
  const out = []
  const walk = (nodes) => { for (const n of (nodes||[])) { if (n.rules!==undefined) out.push(n); walk(n.children) } }
  walk(tree.value)
  return out
})

const visibleFolders = computed(() => activeFolderId.value ? allFolders.value.filter((f)=>f.id===activeFolderId.value) : allFolders.value)

const SNAT_LABELS = {
  NAT_SOURCE_TRANSLATION_TYPE_NONE:'None',
  NAT_SOURCE_TRANSLATION_TYPE_DYNAMIC_IP_PORT:'PAT',
  NAT_SOURCE_TRANSLATION_TYPE_STATIC_IP:'Static IP',
  NAT_SOURCE_TRANSLATION_TYPE_STATIC_IP_PORT:'Static IP+Port',
}
const DNAT_LABELS = {
  NAT_DESTINATION_TRANSLATION_TYPE_NONE:'None',
  NAT_DESTINATION_TRANSLATION_TYPE_ADDRESS_POOL:'DNAT',
}
const snatLabel = (t) => SNAT_LABELS[t] || t
const dnatLabel = (t) => DNAT_LABELS[t] || t

async function loadTree() {
  if (!selectedDeviceId.value) return
  loading.value = true
  try {
    const res = await natApi.getFolderTree({ device_id: selectedDeviceId.value })
    tree.value = Array.isArray(res.data) ? res.data : [res.data]
    loadObjects()
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Failed to load NAT tree')
  } finally {
    loading.value = false
  }
}

async function loadObjects() {
  try {
    const res = await objectsApi.list({ device_id: selectedDeviceId.value })
    const all = res.data||[]
    zoneItems.value = all.filter((o)=>o.type==='zone').map((o)=>({id:o.id,name:o.name}))
    netItems.value = all.filter((o)=>['ip','network','group'].includes(o.type)).map((o)=>({id:o.id,name:o.name}))
    serviceItems.value = all.filter((o)=>o.type==='service').map((o)=>({id:o.id,name:o.name}))
  } catch { /**/ }
}

async function doSync() {
  syncing.value = true
  try {
    await deviceApi.sync(selectedDeviceId.value)
    toast.success('Sync complete'); await loadTree()
  } catch (e) { toast.error(e.response?.data?.detail||'Sync failed') }
  finally { syncing.value = false }
}

async function doDeploy() {
  deploying.value = true
  try {
    await axios.post('/nat/deploy', new URLSearchParams({ device_id: selectedDeviceId.value }))
    toast.success('Deploy successful')
  } catch (e) { toast.error(e.response?.data?.detail||'Deploy failed') }
  finally { deploying.value = false }
}

function openCreate(folderId) {
  editRule.value = null
  form.value = emptyForm()
  form.value.folder_id = folderId || activeFolderId.value || allFolders.value[0]?.id
  showModal.value = true
}

function openEdit(rule, folderId) {
  editRule.value = rule
  form.value = { ...emptyForm(), ...rule, folder_id: folderId }
  showModal.value = true
}

async function submitNat() {
  if (!form.value.name.trim()) { toast.error('Rule name is required'); return }
  saving.value = true
  try {
    const payload = { ...form.value, device_id: selectedDeviceId.value, rule_id: editRule.value?.id }
    if (editRule.value) { await natApi.updateRule(payload); toast.success('Rule updated') }
    else { await natApi.createRule(payload); toast.success('Rule created') }
    showModal.value = false; await loadTree()
  } catch (e) { toast.error(e.response?.data?.detail||'Save failed') }
  finally { saving.value = false }
}

async function toggleRule(rule, enabled) {
  try { await natApi.toggleRule({ rule_id: rule.id, enabled }); rule.enabled = enabled }
  catch (e) { toast.error(e.response?.data?.detail||'Toggle failed'); rule.enabled = !enabled }
}

async function deleteRule(id) {
  try { await natApi.deleteRule({ rule_id: id }); toast.success('Deleted'); await loadTree() }
  catch (e) { toast.error(e.response?.data?.detail||'Delete failed') }
}

async function reorderRules(folder) {
  try { await natApi.reorderRules({ folder_id: folder.id, rule_ids: folder.rules.map((r)=>r.id) }) }
  catch { await loadTree() }
}

async function createFolder() {
  if (!newFolderName.value.trim()) return
  try {
    await axios.post('/nat/create_folder', new URLSearchParams({ device_id:selectedDeviceId.value, folder_name:newFolderName.value, section:newFolderSection.value }))
    toast.success('Folder created'); showFolderModal.value=false; newFolderName.value=''; await loadTree()
  } catch (e) { toast.error(e.response?.data?.detail||'Create failed') }
}

onMounted(async () => {
  await devicesStore.fetchDevices()
  if (devicesStore.currentDevice) { selectedDeviceId.value = devicesStore.currentDevice.id; await loadTree() }
})
</script>

<style scoped>
.modal-backdrop { position:fixed;inset:0;background:rgba(15,23,42,.5);z-index:1050;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(2px) }
.modal-box { background:#fff;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.2);width:90%;max-width:900px;display:flex;flex-direction:column;max-height:90vh }
.modal-xl { max-width:1100px }
.row-btn { padding:3px 6px;border:none;background:transparent;cursor:pointer;color:var(--text-muted);border-radius:4px;font-size:11px;transition:.12s }
.row-btn:hover { background:var(--border);color:var(--text) }
.row-btn.danger:hover { background:#fee2e2;color:var(--danger) }
</style>
