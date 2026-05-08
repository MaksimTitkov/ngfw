<template>
  <div class="folder-card">
    <div class="folder-card-header">
      <span class="folder-card-title">
        <i class="fas fa-folder" style="color:var(--accent)" />
        {{ folder.name }}
      </span>
      <span v-if="folder.section_type" class="section-badge" :class="folder.section_type">
        {{ folder.section_type.toUpperCase() }}
      </span>
      <span style="margin-left:auto;font-size:11px;color:var(--text-muted)">{{ folder.rules?.length || 0 }} rules</span>
      <input
        type="checkbox"
        :checked="allSelected"
        :indeterminate.prop="someSelected && !allSelected"
        @change="$emit('select-all', folder)"
        title="Select all"
        style="cursor:pointer"
      />
    </div>
    <div class="table-scroll">
      <table class="rules-table">
        <colgroup>
          <col style="width:28px">
          <col style="width:28px">
          <col style="width:28px">
          <col style="width:200px">
          <col style="width:120px">
          <col style="width:130px">
          <col style="width:130px">
          <col style="width:130px">
          <col style="width:130px">
          <col style="width:80px">
          <col style="width:80px">
          <col style="width:80px">
          <col style="width:60px">
        </colgroup>
        <thead>
          <tr>
            <th></th>
            <th></th>
            <th>#</th>
            <th>Name</th>
            <th>Src Zone</th>
            <th>Source</th>
            <th>Dst Zone</th>
            <th>Destination</th>
            <th>Service / App</th>
            <th>Action</th>
            <th>Log</th>
            <th>Modified</th>
            <th></th>
          </tr>
        </thead>
        <VueDraggable
          tag="tbody"
          v-model="localRules"
          handle=".drag-handle"
          :animation="150"
          ghost-class="sortable-ghost"
          @end="onReorder"
        >
          <RuleRow
            v-for="rule in localRules"
            :key="rule.id"
            :rule="rule"
            :selected="selectedIds.has(rule.id)"
            @toggle-select="$emit('toggle-select', rule.id)"
            @edit="$emit('edit', rule)"
            @delete="$emit('delete', rule.id)"
            @toggle-enabled="$emit('toggle-enabled', rule.id, $event)"
          />
        </VueDraggable>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { VueDraggable } from 'vue-draggable-plus'
import RuleRow from './RuleRow.vue'

const props = defineProps({
  folder: { type: Object, required: true },
  selectedIds: { type: Set, required: true },
})

const emit = defineEmits(['toggle-select', 'select-all', 'edit', 'delete', 'toggle-enabled', 'reorder'])

const localRules = ref([...(props.folder.rules || [])])

watch(() => props.folder.rules, (v) => { localRules.value = [...(v || [])] })

const allSelected = computed(() => localRules.value.length > 0 && localRules.value.every((r) => props.selectedIds.has(r.id)))
const someSelected = computed(() => localRules.value.some((r) => props.selectedIds.has(r.id)))

function onReorder() {
  emit('reorder', props.folder.id, localRules.value.map((r) => r.id))
}
</script>
