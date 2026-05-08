<template>
  <div class="sidebar-device">
    <div
      class="sidebar-device-header"
      :class="{ open: isOpen }"
      @click="isOpen = !isOpen"
    >
      <i class="fas fa-network-wired" style="color:#3b82f6;font-size:12px;flex-shrink:0" />
      <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ node.name }}</span>
      <button @click.stop="$emit('sync', node.id)" title="Sync" style="background:none;border:none;padding:2px 4px;cursor:pointer;color:#475569;border-radius:4px;flex-shrink:0">
        <i class="fas fa-rotate" style="font-size:10px" />
      </button>
      <i class="fas fa-chevron-right chevron" />
    </div>
    <div v-if="isOpen" class="sidebar-folders open">
      <FolderItem
        v-for="folder in node.folders || node.children || []"
        :key="folder.id"
        :folder="folder"
        :active-id="activeFolderId"
        @select="$emit('select', $event)"
      />
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import FolderItem from './FolderItem.vue'

defineProps({
  node: { type: Object, required: true },
  activeFolderId: { type: [String, Number], default: null },
})
defineEmits(['select', 'sync'])

const isOpen = ref(true)
</script>
