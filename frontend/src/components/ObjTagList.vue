<template>
  <div style="display:flex;flex-wrap:wrap;gap:2px">
    <span v-if="!items?.length" class="rule-any">any</span>
    <template v-else>
      <span
        v-for="(item, i) in visible"
        :key="i"
        class="obj-tag"
        :class="type"
        :title="itemName(item)"
      >
        {{ itemName(item) }}
      </span>
      <span v-if="items.length > maxVisible" class="obj-tag overflow">+{{ items.length - maxVisible }}</span>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  items: { type: Array, default: () => [] },
  type: { type: String, default: '' },
  maxVisible: { type: Number, default: 3 },
})

const visible = computed(() => (props.items || []).slice(0, props.maxVisible))

function itemName(item) {
  if (typeof item === 'string') return item
  return item?.name || item?.id || String(item)
}
</script>
