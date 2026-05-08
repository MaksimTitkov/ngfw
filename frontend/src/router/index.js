import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const routes = [
  { path: '/login', name: 'login', component: () => import('@/views/LoginView.vue'), meta: { public: true } },
  {
    path: '/',
    component: () => import('@/components/AppLayout.vue'),
    children: [
      { path: '',         name: 'index',     component: () => import('@/views/IndexView.vue') },
      { path: 'dashboard',name: 'dashboard', component: () => import('@/views/DashboardView.vue') },
      { path: 'objects',  name: 'objects',   component: () => import('@/views/ObjectsView.vue') },
      { path: 'nat',      name: 'nat',       component: () => import('@/views/NatView.vue') },
      { path: 'logs',     name: 'logs',      component: () => import('@/views/LogsView.vue') },
      { path: 'analyzer', name: 'analyzer',  component: () => import('@/views/AnalyzerView.vue') },
      { path: 'diff',     name: 'diff',      component: () => import('@/views/DiffView.vue') },
      { path: 'changelog',name: 'changelog', component: () => import('@/views/ChangelogView.vue') },
      { path: 'search',   name: 'search',    component: () => import('@/views/SearchView.vue') },
      { path: 'templates',name: 'templates', component: () => import('@/views/TemplatesView.vue') },
      { path: 'system',   name: 'system',    component: () => import('@/views/SystemView.vue') },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to) => {
  if (to.meta.public) return true
  const auth = useAuthStore()
  if (!auth.isAuthenticated) {
    await auth.checkAuth()
  }
  if (!auth.isAuthenticated) {
    return { name: 'login' }
  }
  return true
})

export default router
