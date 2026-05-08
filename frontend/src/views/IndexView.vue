<template>
  <div class="app-topbar">
    <span class="topbar-title"><i class="fas fa-layer-group" style="color:var(--accent);margin-right:6px" />Security Policy</span>
    <div class="topbar-sep" />
    <select v-if="devices.devices.length" v-model="selectedDeviceId" class="form-select" style="width:200px;height:32px;font-size:12px;padding:0 8px" @change="loadTree">
      <option v-for="d in devices.devices" :key="d.id" :value="d.id">{{ d.name }}</option>
    </select>
    <div class="topbar-sep" />
    <button class="btn-top" @click="doSync" :disabled="syncing">
      <i class="fas fa-rotate" :class="{ 'fa-spin': syncing }" />
      {{ syncing ? 'Syncing…' : 'Sync' }}
    </button>
    <button v-if="!auth.isReadOnly" class="btn-top primary" @click="doDeploy" :disabled="deploying">
      <i class="fas fa-rocket" :class="{ 'fa-spin': deploying }" />
      {{ deploying ? 'Deploying…' : 'Deploy' }}
    </button>
    <div style="margin-left:auto;display:flex;align-items:center;gap:8px">
      <template v-if="!auth.isReadOnly">
        <button class="btn-top" @click="showCreateFolder = true">
          <i class="fas fa-folder-plus" /> New Folder
        </button>
        <button class="btn-top primary" @click="openCreateRule">
          <i class="fas fa-plus" /> Add Rule
        </button>
      </template>
    </div>
  </div>

  <!-- Main content split: sidebar folders + rules table -->
  <div style="display:flex;flex:1;overflow:hidden">
    <!-- Folder tree in sidebar slot is managed by AppLayout/AppSidebar -->
    <!-- For now render folder tree inline in a left panel -->
    <div style="width:220px;border-right:1px solid var(--border);background:var(--surface);overflow-y:auto;padding:8px 0;flex-shrink:0">
      <div class="sidebar-section-label">Folders</div>
      <FolderTreeItem
        v-for="device in tree"
        :key="device.id"
        :node="device"
        :active-folder-id="activeFolderId"
        @select="activeFolderId = $event"
        @sync="doSync"
      />
    </div>

    <!-- Rules table -->
    <div class="app-content" style="flex:1">
      <template v-if="loading">
        <div class="empty-state"><div class="spinner-ring" style="margin:0 auto 12px" /><div>Loading rules…</div></div>
      </template>
      <template v-else-if="visibleFolders.length === 0">
        <div class="empty-state">
          <i class="fas fa-layer-group" />
          <div style="margin-top:8px">No rules found. Sync a device or select a folder.</div>
        </div>
      </template>
      <template v-else>
        <FolderCard
          v-for="folder in visibleFolders"
          :key="folder.id"
          :folder="folder"
          :selected-ids="selectedIds"
          @toggle-select="toggleSelect"
          @select-all="selectAll(folder)"
          @edit="openEditRule"
          @delete="deleteRule"
          @toggle-enabled="toggleRule"
          @reorder="reorderRules"
        />
      </template>
    </div>
  </div>

  <!-- Bulk action bar -->
  <div v-if="selectedIds.size > 0" class="bulk-bar">
    <span class="bulk-bar-count">{{ selectedIds.size }} selected</span>
    <div class="bulk-sep" />
    <button class="btn-bulk green" @click="bulkToggle(true)"><i class="fas fa-eye" /> Enable</button>
    <button class="btn-bulk red" @click="bulkToggle(false)"><i class="fas fa-eye-slash" /> Disable</button>
    <div class="bulk-sep" />
    <button class="btn-bulk light" @click="selectedIds.clear()"><i class="fas fa-times" /> Clear</button>
  </div>

  <!-- Loading overlay -->
  <div v-if="syncing || deploying" class="loading-overlay">
    <div class="spinner-ring" />
    <div style="font-size:14px;font-weight:600">{{ syncing ? 'Syncing device…' : 'Deploying policy…' }}</div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { useDevicesStore } from '@/stores/devices'
import { useToastStore } from '@/stores/toast'
import { useAuthStore } from '@/stores/auth'
import { rulesApi, deviceApi } from '@/api'
import FolderCard from '@/components/FolderCard.vue'
import FolderTreeItem from '@/components/FolderTreeItem.vue'

const devices = useDevicesStore()
const toast = useToastStore()
const auth = useAuthStore()

const selectedDeviceId = ref(null)
const tree = ref([])
const loading = ref(false)
const syncing = ref(false)
const deploying = ref(false)
const activeFolderId = ref(null)
const selectedIds = ref(new Set())
const showCreateFolder = ref(false)

const visibleFolders = computed(() => {
  if (!activeFolderId.value) return allFolders.value
  return allFolders.value.filter((f) => f.id === activeFolderId.value)
})

const allFolders = computed(() => {
  const result = []
  const flatten = (nodes) => {
    for (const n of nodes) {
      if (n.rules) result.push(n)
      if (n.children) flatten(n.children)
    }
  }
  flatten(tree.value)
  return result
})

async function loadTree() {
  if (!selectedDeviceId.value) return
  loading.value = true
  try {
    const res = await rulesApi.getFolderTree({ device_id: selectedDeviceId.value })
    tree.value = Array.isArray(res.data) ? res.data : [res.data]
  } catch (e) {
    toast.error('Failed to load rules: ' + (e.response?.data?.detail || e.message))
  } finally {
    loading.value = false
  }
}

async function doSync() {
  syncing.value = true
  try {
    await deviceApi.sync(selectedDeviceId.value)
    toast.success('Sync complete')
    await loadTree()
  } catch (e) {
    toast.error('Sync failed: ' + (e.response?.data?.detail || e.message))
  } finally {
    syncing.value = false
  }
}

async function doDeploy() {
  if (!selectedDeviceId.value) return
  deploying.value = true
  try {
    await deviceApi.commit(new URLSearchParams({ device_id: selectedDeviceId.value }))
    toast.success('Deploy successful')
  } catch (e) {
    toast.error('Deploy failed: ' + (e.response?.data?.detail || e.message))
  } finally {
    deploying.value = false
  }
}

function toggleSelect(ruleId) {
  if (selectedIds.value.has(ruleId)) selectedIds.value.delete(ruleId)
  else selectedIds.value.add(ruleId)
  selectedIds.value = new Set(selectedIds.value)
}

function selectAll(folder) {
  folder.rules.forEach((r) => selectedIds.value.add(r.id))
  selectedIds.value = new Set(selectedIds.value)
}

async function bulkToggle(enabled) {
  try {
    await rulesApi.bulkToggle({ rule_ids: [...selectedIds.value], enabled })
    toast.success(`${selectedIds.value.size} rules ${enabled ? 'enabled' : 'disabled'}`)
    selectedIds.value.clear()
    await loadTree()
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Bulk action failed')
  }
}

async function deleteRule(ruleId) {
  try {
    await rulesApi.delete({ rule_id: ruleId })
    toast.success('Rule deleted')
    await loadTree()
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Delete failed')
  }
}

async function toggleRule(ruleId, enabled) {
  try {
    await rulesApi.toggle({ rule_id: ruleId, enabled })
    await loadTree()
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Toggle failed')
  }
}

async function reorderRules(folderId, orderedIds) {
  try {
    await rulesApi.reorder({ folder_id: folderId, rule_ids: orderedIds })
  } catch (e) {
    toast.error(e.response?.data?.detail || 'Reorder failed')
    await loadTree()
  }
}

function openCreateRule() {
  // TODO: emit to modal
}

function openEditRule(rule) {
  // TODO: emit to modal
}

onMounted(async () => {
  await devices.fetchDevices()
  if (devices.currentDevice) {
    selectedDeviceId.value = devices.currentDevice.id
    await loadTree()
  }
})

watch(() => devices.currentDevice, (d) => {
  if (d && d.id !== selectedDeviceId.value) {
    selectedDeviceId.value = d.id
    loadTree()
  }
})
</script>
