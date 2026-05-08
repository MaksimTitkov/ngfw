<template>
  <tr :class="{ selected, 'rule-disabled': !rule.enabled }" @click="$emit('toggle-select')">
    <td class="drag-handle" @click.stop><i class="fas fa-grip-vertical" /></td>
    <td @click.stop>
      <input type="checkbox" :checked="selected" @change="$emit('toggle-select')" style="cursor:pointer" />
    </td>
    <td style="color:var(--text-muted);font-size:11px">{{ rule.position }}</td>
    <td>
      <div class="rule-name" :style="!rule.enabled ? 'text-decoration:line-through;opacity:.5' : ''">{{ rule.name }}</div>
      <div v-if="rule.description" style="font-size:11px;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:190px">{{ rule.description }}</div>
    </td>
    <td><ObjTagList :items="rule.src_zones" type="zone" /></td>
    <td><ObjTagList :items="rule.src_ips" type="" /></td>
    <td><ObjTagList :items="rule.dst_zones" type="zone" /></td>
    <td><ObjTagList :items="rule.dst_ips" type="" /></td>
    <td><ObjTagList :items="[...(rule.services||[]), ...(rule.apps||[])]" type="service" /></td>
    <td>
      <span class="action-badge" :class="rule.action">{{ rule.action }}</span>
    </td>
    <td>
      <i v-if="rule.log" class="fas fa-check" style="color:var(--success)" />
      <i v-else class="fas fa-times" style="color:var(--text-light)" />
    </td>
    <td style="font-size:11px;color:var(--text-muted)">
      <span v-if="rule.modified_at">{{ formatDate(rule.modified_at) }}</span>
    </td>
    <td @click.stop>
      <div style="display:flex;gap:3px;justify-content:flex-end">
        <button class="row-btn" @click="$emit('toggle-enabled', !rule.enabled)" :title="rule.enabled ? 'Disable' : 'Enable'">
          <i :class="rule.enabled ? 'fas fa-eye' : 'fas fa-eye-slash'" />
        </button>
        <button class="row-btn" @click="$emit('edit', rule)" title="Edit">
          <i class="fas fa-pen" />
        </button>
        <button class="row-btn danger" @click="$emit('delete', rule.id)" title="Delete">
          <i class="fas fa-trash" />
        </button>
      </div>
    </td>
  </tr>
</template>

<script setup>
import ObjTagList from './ObjTagList.vue'

defineProps({
  rule: { type: Object, required: true },
  selected: { type: Boolean, default: false },
})
defineEmits(['toggle-select', 'edit', 'delete', 'toggle-enabled'])

function formatDate(dt) {
  if (!dt) return ''
  return new Date(dt).toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit' })
}
</script>

<style scoped>
.rule-disabled { opacity: .6; }
.row-btn {
  padding: 3px 6px; border: none; background: transparent;
  cursor: pointer; color: var(--text-muted); border-radius: 4px;
  font-size: 11px; transition: all .12s;
}
.row-btn:hover { background: var(--border); color: var(--text); }
.row-btn.danger:hover { background: #fee2e2; color: var(--danger); }
</style>
