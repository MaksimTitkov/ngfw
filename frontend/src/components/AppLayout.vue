<template>
  <div class="app-layout">
    <AppSidebar :analyzer-issue-count="analyzerIssueCount">
      <slot name="sidebar" />
    </AppSidebar>
    <div class="app-main">
      <router-view />
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import AppSidebar from './AppSidebar.vue'
import { analyzerApi } from '@/api'

const analyzerIssueCount = ref(0)

onMounted(async () => {
  try {
    const res = await analyzerApi.cached()
    analyzerIssueCount.value = res.data?.issue_count ?? 0
  } catch {
    // not critical
  }
})
</script>
