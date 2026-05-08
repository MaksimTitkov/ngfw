<template>
  <aside class="app-sidebar">
    <!-- Brand -->
    <div class="sidebar-brand">
      <div style="width:32px;height:32px;background:linear-gradient(135deg,#1d4ed8,#3b82f6);border-radius:8px;display:flex;align-items:center;justify-content:center;margin-right:10px;flex-shrink:0">
        <i class="fas fa-shield-halved" style="color:#fff;font-size:15px" />
      </div>
      <div>
        <div class="sidebar-brand-text">NGFW Manager</div>
        <span class="sidebar-brand-sub">Policy Editor</span>
      </div>
    </div>

    <!-- Section tabs -->
    <div style="display:flex;gap:3px;padding:8px 10px 0">
      <router-link
        v-for="tab in mainTabs"
        :key="tab.section"
        :to="tab.href"
        class="sidebar-tab"
        :class="{ active: activeSection === tab.section }"
        :title="tab.title"
      >
        <i :class="tab.icon" style="font-size:11px;display:block;margin-bottom:2px" />
        {{ tab.label }}
        <span v-if="tab.badge" class="sidebar-tab-badge">{{ tab.badge }}</span>
      </router-link>
    </div>

    <!-- Sub-nav -->
    <div style="display:flex;gap:2px;padding:0 10px 5px;border-bottom:1px solid rgba(255,255,255,.07);background:rgba(255,255,255,.02)">
      <router-link
        v-for="sub in subTabs"
        :key="sub.href"
        :to="sub.href"
        class="sidebar-subtab"
        :class="{ active: route.path === sub.href }"
      >
        {{ sub.label }}
      </router-link>
    </div>

    <!-- Scroll area -->
    <div class="sidebar-scroll">
      <slot />
    </div>

    <!-- Footer -->
    <div class="sidebar-footer">
      <div style="width:28px;height:28px;background:var(--accent);border-radius:6px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
        <i class="fas fa-user" style="color:#fff;font-size:11px" />
      </div>
      <div class="sidebar-user">
        <div class="sidebar-user-name">
          {{ auth.user?.username || 'Admin' }}
          <span v-if="auth.isReadOnly" style="font-size:9px;background:#334155;color:#94a3b8;padding:1px 5px;border-radius:4px;margin-left:4px;font-weight:700">RO</span>
        </div>
        <div class="sidebar-user-host">NGFW Manager 2.0</div>
      </div>
      <button @click="auth.logout()" style="background:none;border:none;cursor:pointer;color:#475569;padding:4px 6px;border-radius:4px;transition:.15s"
              title="Logout" @mouseenter="e => e.target.style.color='#ef4444'" @mouseleave="e => e.target.style.color='#475569'">
        <i class="fas fa-right-from-bracket" style="font-size:13px" />
      </button>
    </div>
  </aside>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const route = useRoute()
const auth = useAuthStore()

const props = defineProps({
  analyzerIssueCount: { type: Number, default: 0 },
})

const activeSection = computed(() => {
  const p = route.path
  if (['/', '/nat', '/objects'].includes(p)) return 'sec'
  if (p === '/logs') return 'log'
  if (['/system', '/policy'].includes(p)) return 'sys'
  return 'dash'
})

const mainTabs = computed(() => [
  { section: 'sec',  href: '/',          icon: 'fas fa-layer-group', label: 'SEC',  title: 'Security Policy' },
  { section: 'log',  href: '/logs',       icon: 'fas fa-list-alt',   label: 'LOG',  title: 'Traffic & Logs' },
  { section: 'sys',  href: '/system',     icon: 'fas fa-server',     label: 'SYS',  title: 'System' },
  { section: 'dash', href: '/dashboard',  icon: 'fas fa-gauge-high', label: 'DASH', title: 'Dashboard',
    badge: props.analyzerIssueCount > 0 ? props.analyzerIssueCount : null },
])

const subTabs = computed(() => {
  const s = activeSection.value
  if (s === 'sec')  return [{ href: '/', label: 'Rules' }, { href: '/nat', label: 'NAT' }, { href: '/objects', label: 'Objects' }]
  if (s === 'log')  return [{ href: '/logs', label: 'Traffic & Logs' }]
  if (s === 'sys')  return [{ href: '/system', label: 'System' }, { href: '/policy', label: 'Policy' }]
  return [
    { href: '/dashboard',  label: 'Overview' },
    { href: '/analyzer',   label: 'Analyzer' },
    { href: '/changelog',  label: 'Changes' },
    { href: '/diff',       label: 'Diff' },
  ]
})
</script>

<style scoped>
.sidebar-tab {
  flex: 1; text-align: center; padding: 7px 4px;
  border-radius: 7px 7px 0 0; font-size: 10px; font-weight: 700;
  text-decoration: none; transition: .15s; position: relative;
  background: rgba(255,255,255,.04); color: #4b5563;
  border-bottom: 2px solid transparent;
}
.sidebar-tab.active { background: rgba(59,130,246,.2); color: #60a5fa; border-bottom-color: #3b82f6; }
.sidebar-tab-badge {
  position: absolute; top: 3px; right: 3px;
  background: #ef4444; color: #fff; font-size: 8px; font-weight: 800;
  padding: 1px 3px; border-radius: 8px; line-height: 1.4; min-width: 13px; text-align: center;
}
.sidebar-subtab {
  flex: 1; text-align: center; padding: 3px 2px;
  font-size: 9px; font-weight: 700; text-decoration: none;
  color: #374151; border-bottom: 2px solid transparent; transition: .15s;
}
.sidebar-subtab.active { color: #93c5fd; border-bottom-color: #3b82f6; }
</style>
