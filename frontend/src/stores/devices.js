import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'

export const useDevicesStore = defineStore('devices', () => {
  const devices = ref([])
  const currentDevice = ref(null)
  const syncing = ref(false)

  async function fetchDevices() {
    try {
      const res = await axios.get('/api/v1/devices/list')
      devices.value = res.data
      if (!currentDevice.value && devices.value.length) {
        currentDevice.value = devices.value[0]
      }
    } catch {
      // silently fail — may not be authenticated yet
    }
  }

  function setDevice(device) {
    currentDevice.value = device
  }

  return { devices, currentDevice, syncing, fetchDevices, setDevice }
})
