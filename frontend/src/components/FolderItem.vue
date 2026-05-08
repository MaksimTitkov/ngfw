<template>
  <div>
    <div
      class="folder-link"
      :class="{ active: folder.id === activeId }"
      @click="$emit('select', folder.id)"
    >
      <i class="fas fa-folder" style="font-size:11px;flex-shrink:0" />
      <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ folder.name }}</span>
      <span v-if="folder.rule_count !== undefined" class="folder-count">{{ folder.rule_count }}</span>
    </div>
    <div v-if="folder.children?.length" style="padding-left:12px">
      <FolderItem
        v-for="child in folder.children"
        :key="child.id"
        :folder="child"
        :active-id="activeId"
        @select="$emit('select', $event)"
      />
    </div>
  </div>
</template>

<script setup>
defineProps({
  folder: { type: Object, required: true },
  activeId: { type: [String, Number], default: null },
})
defineEmits(['select'])
</script>
