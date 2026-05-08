<template>
  <div class="app-topbar">
    <span class="topbar-title"><i class="fas fa-server" style="color:#3b82f6;margin-right:6px" />System Management</span>
    <div class="topbar-sep" />
    <div style="display:flex;gap:4px">
      <button v-for="tab in tabs" :key="tab.key" @click="setTab(tab.key)"
              :class="['sys-tab', activeTab===tab.key?'sys-tab-active':'']">
        <i :class="`fas ${tab.icon} me-1`" />{{ tab.label }}
      </button>
    </div>
    <div class="topbar-sep" />
    <button @click="loadTab" style="padding:5px 10px;border-radius:8px;border:1px solid #e2e8f0;background:#fff;color:#374151;font-size:12px;font-weight:600;cursor:pointer">
      <i class="fas fa-sync-alt" />
    </button>
    <div style="margin-left:auto">
      <select v-model="selectedDeviceId" class="form-select" style="width:180px;height:32px;font-size:12px;padding:0 8px" @change="loadTab">
        <option v-for="d in devicesStore.devices" :key="d.id" :value="d.id">{{ d.name }}</option>
      </select>
    </div>
  </div>

  <div style="flex:1;overflow:auto;padding:20px">
    <div v-if="loading" class="empty-state"><div class="spinner-ring" style="margin:0 auto 12px" /></div>

    <!-- BACKUP TAB -->
    <template v-if="activeTab==='backup' && !loading">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
        <h5 style="margin:0;font-weight:700">Backups</h5>
        <button class="btn-top primary" @click="createBackup"><i class="fas fa-plus" /> Create Backup</button>
      </div>
      <div v-if="!backups.length" class="empty-state"><i class="fas fa-database" /><div style="margin-top:8px">No backups yet</div></div>
      <div v-else class="folder-card">
        <table class="rules-table">
          <thead><tr><th>Name</th><th>Size</th><th>Created</th><th></th></tr></thead>
          <tbody>
            <tr v-for="b in backups" :key="b.id">
              <td class="rule-name">{{ b.name }}</td>
              <td style="font-size:12px;color:var(--text-muted)">{{ b.size }}</td>
              <td style="font-size:12px;color:var(--text-muted)">{{ fmtDt(b.created_at) }}</td>
              <td style="text-align:right">
                <button class="row-btn danger" @click="deleteBackup(b.id)"><i class="fas fa-trash" /></button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- INTERFACES TAB -->
    <template v-if="activeTab==='interfaces' && !loading">
      <h5 style="font-weight:700;margin-bottom:16px">Network Interfaces</h5>
      <div v-if="!interfaces.length" class="empty-state"><i class="fas fa-network-wired" /><div style="margin-top:8px">No interfaces data</div></div>
      <div v-else class="folder-card">
        <table class="rules-table">
          <thead><tr><th>Name</th><th>IP Address</th><th>Mask</th><th>Status</th><th>Mode</th></tr></thead>
          <tbody>
            <tr v-for="iface in interfaces" :key="iface.name">
              <td class="rule-name">{{ iface.name }}</td>
              <td style="font-family:monospace;font-size:12px">{{ iface.ip || '—' }}</td>
              <td style="font-family:monospace;font-size:12px">{{ iface.mask || '—' }}</td>
              <td>
                <span :style="`display:inline-block;padding:1px 8px;border-radius:20px;font-size:10px;font-weight:700;background:${iface.enabled?'#dcfce7':'#f1f5f9'};color:${iface.enabled?'#166534':'#64748b'}`">
                  {{ iface.enabled ? 'UP' : 'DOWN' }}
                </span>
              </td>
              <td style="font-size:12px;color:var(--text-muted)">{{ iface.mode || '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- SETTINGS TAB (admins + timeouts) -->
    <template v-if="activeTab==='settings' && !loading">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
        <!-- Admins -->
        <div>
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
            <h5 style="margin:0;font-weight:700">Administrators</h5>
            <button class="btn-top primary" @click="showAdminModal=true"><i class="fas fa-plus" /> Create Admin</button>
          </div>
          <div class="folder-card">
            <table class="rules-table">
              <thead><tr><th>Login</th><th>Name</th><th>Role</th><th></th></tr></thead>
              <tbody>
                <tr v-if="!admins.length"><td colspan="4" style="text-align:center;padding:20px;color:#94a3b8;font-size:12px">No admins</td></tr>
                <tr v-for="a in admins" :key="a.id">
                  <td class="rule-name">{{ a.login || a.username }}</td>
                  <td style="font-size:12px">{{ a.name || '—' }}</td>
                  <td><span class="section-badge default">{{ a.role }}</span></td>
                  <td style="text-align:right;display:flex;gap:4px;justify-content:flex-end">
                    <button class="row-btn" @click="openPwModal(a)" title="Change Password"><i class="fas fa-key" /></button>
                    <button class="row-btn danger" @click="deleteAdmin(a.id)" title="Delete"><i class="fas fa-trash" /></button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Timeouts -->
        <div>
          <h5 style="font-weight:700;margin-bottom:12px">Connection Timeouts</h5>
          <div class="folder-card" style="padding:16px">
            <div v-if="!timeouts || !Object.keys(timeouts).length" style="color:var(--text-muted);font-size:13px">No timeout data</div>
            <div v-else>
              <div v-for="(val, key) in timeouts" :key="key" style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border)">
                <span style="font-size:12px;font-weight:600;color:var(--text-muted)">{{ key }}</span>
                <div style="display:flex;align-items:center;gap:8px">
                  <input v-model="timeoutsEdit[key]" type="number" style="width:80px;padding:3px 6px;border:1px solid var(--border);border-radius:6px;font-size:12px;text-align:right" />
                  <span style="font-size:11px;color:var(--text-muted)">sec</span>
                </div>
              </div>
              <button class="btn-top primary" style="margin-top:12px;width:100%" @click="saveTimeouts">
                <i class="fas fa-save" /> Save Timeouts
              </button>
            </div>
          </div>
        </div>
      </div>
    </template>

    <!-- SCHEDULER TAB -->
    <template v-if="activeTab==='scheduler' && !loading">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
        <h5 style="margin:0;font-weight:700">Scheduled Tasks</h5>
        <button class="btn-top primary" @click="showTaskModal=true"><i class="fas fa-plus" /> New Task</button>
      </div>
      <div v-if="!tasks.length" class="empty-state"><i class="fas fa-clock" /><div style="margin-top:8px">No scheduled tasks</div></div>
      <div v-else class="folder-card">
        <table class="rules-table">
          <thead><tr><th>Name</th><th>Type</th><th>Schedule</th><th>Last Run</th><th>Status</th><th></th></tr></thead>
          <tbody>
            <tr v-for="t in tasks" :key="t.id">
              <td class="rule-name">{{ t.name }}</td>
              <td style="font-size:12px">{{ t.task_type }}</td>
              <td style="font-size:12px;font-family:monospace">{{ t.cron_expr || t.interval || '—' }}</td>
              <td style="font-size:11px;color:var(--text-muted)">{{ t.last_run_at ? fmtDt(t.last_run_at) : 'Never' }}</td>
              <td>
                <span :style="`display:inline-block;padding:1px 8px;border-radius:20px;font-size:10px;font-weight:700;background:${t.enabled?'#dcfce7':'#f1f5f9'};color:${t.enabled?'#166534':'#64748b'}`">
                  {{ t.enabled ? 'Active' : 'Disabled' }}
                </span>
              </td>
              <td>
                <div style="display:flex;gap:4px;justify-content:flex-end">
                  <button class="row-btn" @click="runTask(t.id)" title="Run Now"><i class="fas fa-play" /></button>
                  <button class="row-btn danger" @click="deleteTask(t.id)" title="Delete"><i class="fas fa-trash" /></button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>

  <!-- Create Admin Modal -->
  <div v-if="showAdminModal" class="modal-backdrop" @click.self="showAdminModal=false">
    <div class="modal-box" style="max-width:420px">
      <div class="modal-header"><h5 class="modal-title">Create Admin</h5><button class="btn-close" @click="showAdminModal=false" /></div>
      <div class="modal-body">
        <div class="mb-3"><label class="form-label-sm">Login *</label><input v-model="adminForm.login" class="form-control form-control-sm" placeholder="admin_user" /></div>
        <div class="mb-3"><label class="form-label-sm">Name</label><input v-model="adminForm.name" class="form-control form-control-sm" placeholder="Full Name" /></div>
        <div class="mb-3"><label class="form-label-sm">Password *</label><input v-model="adminForm.password" type="password" class="form-control form-control-sm" /></div>
        <div><label class="form-label-sm">Role</label>
          <select v-model="adminForm.role" class="form-select form-select-sm">
            <option value="SuperAdmin">Super Admin</option>
            <option value="Admin">Admin</option>
            <option value="ReadOnly" selected>Read Only</option>
            <option value="Auditor">Auditor</option>
          </select>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-light btn-sm" @click="showAdminModal=false">Cancel</button>
        <button class="btn btn-primary btn-sm fw-bold" @click="createAdmin"><i class="fas fa-plus me-1" />Create</button>
      </div>
    </div>
  </div>

  <!-- Change Password Modal -->
  <div v-if="showPwModal" class="modal-backdrop" @click.self="showPwModal=false">
    <div class="modal-box" style="max-width:340px">
      <div class="modal-header"><h5 class="modal-title">Change Password</h5><button class="btn-close" @click="showPwModal=false" /></div>
      <div class="modal-body">
        <label class="form-label-sm">New Password *</label>
        <input v-model="newPassword" type="password" class="form-control form-control-sm" />
      </div>
      <div class="modal-footer">
        <button class="btn btn-light btn-sm" @click="showPwModal=false">Cancel</button>
        <button class="btn btn-warning btn-sm fw-bold" @click="savePassword">Save Password</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useDevicesStore } from '@/stores/devices'
import { useToastStore } from '@/stores/toast'
import { systemApi, schedulerApi } from '@/api'

const devicesStore = useDevicesStore()
const toast = useToastStore()

const selectedDeviceId = ref(null)
const activeTab = ref('backup')
const loading = ref(false)

const backups = ref([])
const interfaces = ref([])
const admins = ref([])
const timeouts = ref({})
const timeoutsEdit = ref({})
const tasks = ref([])

const showAdminModal = ref(false)
const showPwModal = ref(false)
const showTaskModal = ref(false)
const adminForm = ref({ login:'', name:'', password:'', role:'ReadOnly' })
const newPassword = ref('')
const selectedAdminId = ref(null)

const tabs = [
  { key:'backup',     label:'Backup',     icon:'fa-database' },
  { key:'interfaces', label:'Interfaces', icon:'fa-network-wired' },
  { key:'settings',   label:'Settings',   icon:'fa-sliders' },
  { key:'scheduler',  label:'Scheduler',  icon:'fa-clock' },
]

function setTab(t) { activeTab.value = t; loadTab() }

async function loadTab() {
  if (!selectedDeviceId.value) return
  loading.value = true
  try {
    if (activeTab.value === 'backup') {
      const res = await systemApi.getBackups()
      backups.value = res.data || []
    } else if (activeTab.value === 'interfaces') {
      const res = await systemApi.getInterfaces()
      interfaces.value = res.data || []
    } else if (activeTab.value === 'settings') {
      const [aRes, tRes] = await Promise.all([systemApi.getAdmins(), systemApi.getTimeouts()])
      admins.value = aRes.data || []
      timeouts.value = tRes.data || {}
      timeoutsEdit.value = { ...tRes.data }
    } else if (activeTab.value === 'scheduler') {
      const res = await schedulerApi.list()
      tasks.value = res.data || []
    }
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Load failed')
  } finally {
    loading.value = false
  }
}

async function createBackup() {
  try { await systemApi.createBackup({ device_id: selectedDeviceId.value }); toast.success('Backup created'); await loadTab() }
  catch (e) { toast.error(e.response?.data?.detail || 'Backup failed') }
}

async function deleteBackup(id) {
  if (!confirm('Delete this backup?')) return
  try { await systemApi.deleteBackup({ backup_id: id }); toast.success('Deleted'); await loadTab() }
  catch (e) { toast.error(e.response?.data?.detail || 'Delete failed') }
}

async function createAdmin() {
  try { await systemApi.createAdmin({ ...adminForm.value, device_id: selectedDeviceId.value }); toast.success('Admin created'); showAdminModal.value = false; await loadTab() }
  catch (e) { toast.error(e.response?.data?.detail || 'Create failed') }
}

async function deleteAdmin(id) {
  if (!confirm('Delete this admin?')) return
  try { await systemApi.adminAction({ admin_id: id, action: 'delete' }); toast.success('Deleted'); await loadTab() }
  catch (e) { toast.error(e.response?.data?.detail || 'Delete failed') }
}

function openPwModal(a) { selectedAdminId.value = a.id; newPassword.value = ''; showPwModal.value = true }

async function savePassword() {
  try { await systemApi.changePassword({ admin_id: selectedAdminId.value, password: newPassword.value }); toast.success('Password changed'); showPwModal.value = false }
  catch (e) { toast.error(e.response?.data?.detail || 'Save failed') }
}

async function saveTimeouts() {
  try { await systemApi.setTimeouts(timeoutsEdit.value); toast.success('Timeouts saved') }
  catch (e) { toast.error(e.response?.data?.detail || 'Save failed') }
}

async function runTask(id) {
  try { await schedulerApi.run(id); toast.success('Task started') }
  catch (e) { toast.error(e.response?.data?.detail || 'Run failed') }
}

async function deleteTask(id) {
  if (!confirm('Delete this task?')) return
  try { await schedulerApi.delete(id); toast.success('Deleted'); await loadTab() }
  catch (e) { toast.error(e.response?.data?.detail || 'Delete failed') }
}

function fmtDt(dt) {
  if (!dt) return ''
  return new Date(dt).toLocaleString('ru-RU', { day:'2-digit', month:'2-digit', year:'2-digit', hour:'2-digit', minute:'2-digit' })
}

onMounted(async () => {
  await devicesStore.fetchDevices()
  if (devicesStore.currentDevice) { selectedDeviceId.value = devicesStore.currentDevice.id; await loadTab() }
})
</script>

<style scoped>
.sys-tab { padding:4px 11px;border-radius:6px;border:none;font-size:11px;font-weight:600;cursor:pointer;transition:.15s;background:#f1f5f9;color:#64748b }
.sys-tab-active { background:#3b82f6;color:#fff }
.sys-tab:hover:not(.sys-tab-active) { background:#e2e8f0 }
.modal-backdrop { position:fixed;inset:0;background:rgba(15,23,42,.5);z-index:1050;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(2px) }
.modal-box { background:#fff;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.2);width:90%;display:flex;flex-direction:column;max-height:90vh }
.row-btn { padding:3px 6px;border:none;background:transparent;cursor:pointer;color:var(--text-muted);border-radius:4px;font-size:11px }
.row-btn:hover { background:var(--border) }
.row-btn.danger:hover { background:#fee2e2;color:var(--danger) }
</style>
