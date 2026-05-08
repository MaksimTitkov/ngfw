<template>
  <div class="picker-wrap" ref="wrap">
    <div class="picker-tags" @click="focusInput">
      <span
        v-for="item in selected"
        :key="item.id"
        class="picker-tag"
        :class="tagClass"
      >
        <span :title="item.name" style="max-width:150px;overflow:hidden;text-overflow:ellipsis">{{ item.name }}</span>
        <span class="picker-tag-rm" @click.stop="deselect(item.id)">&times;</span>
      </span>
      <input
        ref="input"
        class="picker-input"
        v-model="query"
        :placeholder="selected.length ? '' : placeholder"
        autocomplete="off"
        spellcheck="false"
        @focus="open = true"
        @blur="onBlur"
        @keydown="onKey"
      />
    </div>
    <div v-if="open" class="picker-dropdown">
      <div v-if="filtered.length === 0" class="picker-empty">
        {{ query ? 'No matches' : 'All objects selected or none available' }}
      </div>
      <template v-else>
        <div
          v-for="item in filtered.slice(0, 100)"
          :key="item.id"
          class="picker-item"
          @mousedown.prevent="select(item)"
        >
          <span v-if="item.global" class="global-badge">G</span>
          <span v-html="highlight(item.name)" />
        </div>
        <div v-if="filtered.length > 100" class="picker-empty">… {{ filtered.length - 100 }} more, refine search</div>
      </template>
      <div v-if="onCreateNew && query" class="picker-create-item" @mousedown.prevent="triggerCreate">
        <i class="fas fa-plus-circle" style="flex-shrink:0" />
        <span>Create <b>"{{ query }}"</b></span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const props = defineProps({
  items: { type: Array, default: () => [] },
  modelValue: { type: Array, default: () => [] },
  placeholder: { type: String, default: 'Search objects...' },
  tagClass: { type: String, default: '' },
  onCreateNew: { type: Function, default: null },
})

const emit = defineEmits(['update:modelValue'])

const query = ref('')
const open = ref(false)
const input = ref(null)

const selected = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const filtered = computed(() => {
  const q = query.value.toLowerCase().trim()
  const selIds = new Set(selected.value.map((s) => s.id))
  return props.items.filter((it) => {
    if (selIds.has(it.id)) return false
    return !q || it.name.toLowerCase().includes(q)
  })
})

function select(item) {
  if (!selected.value.find((s) => s.id === item.id)) {
    emit('update:modelValue', [...selected.value, { id: item.id, name: item.name }])
  }
  query.value = ''
}

function deselect(id) {
  emit('update:modelValue', selected.value.filter((s) => s.id !== id))
}

function focusInput() {
  input.value?.focus()
}

function onBlur() {
  setTimeout(() => { open.value = false }, 150)
}

function onKey(e) {
  if (e.key === 'Backspace' && !query.value && selected.value.length) {
    const last = selected.value[selected.value.length - 1]
    deselect(last.id)
  }
  if (e.key === 'Escape') open.value = false
}

function triggerCreate() {
  if (props.onCreateNew) {
    const q = query.value
    query.value = ''
    open.value = false
    props.onCreateNew(q, (item) => {
      if (item?.id) select(item)
    })
  }
}

function highlight(name) {
  const q = query.value.toLowerCase().trim()
  if (!q) return esc(name)
  const idx = name.toLowerCase().indexOf(q)
  if (idx === -1) return esc(name)
  return esc(name.slice(0, idx)) +
    '<mark style="background:#dbeafe;padding:0;border-radius:2px">' +
    esc(name.slice(idx, idx + q.length)) +
    '</mark>' +
    esc(name.slice(idx + q.length))
}

function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}
</script>
