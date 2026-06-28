<template>
  <div class="min-h-screen bg-slate-900 text-slate-100 font-sans selection:bg-teal-500 selection:text-white">
    <!-- Header -->
    <header class="border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
      <div class="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 rounded-lg bg-gradient-to-br from-teal-400 to-emerald-600 flex items-center justify-center shadow-lg shadow-teal-500/20">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 class="text-xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-teal-200 to-emerald-400">
            Security Scanner
          </h1>
        </div>
      </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 py-12">
      <!-- Search Section -->
      <section class="max-w-3xl mx-auto text-center space-y-8 mb-16">
        <h2 class="text-4xl md:text-5xl font-extrabold tracking-tight">
          Analyze your web application's <br/>
          <span class="text-transparent bg-clip-text bg-gradient-to-r from-teal-400 to-emerald-500">security posture.</span>
        </h2>
        <p class="text-slate-400 text-lg max-w-2xl mx-auto">
          Perform a comprehensive health check on HTTP headers, form compliance, and network fingerprints in seconds.
        </p>

        <form @submit.prevent="runScan" class="relative group">
          <div class="absolute -inset-1 bg-gradient-to-r from-teal-500 to-emerald-500 rounded-2xl blur opacity-25 group-hover:opacity-40 transition duration-1000 group-hover:duration-200"></div>
          <div class="relative flex items-center bg-slate-800 rounded-xl overflow-hidden border border-slate-700 shadow-2xl">
            <div class="pl-4 pr-2 text-slate-400">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
              </svg>
            </div>
            <input 
              v-model="targetUrl" 
              type="url" 
              placeholder="https://example.com" 
              class="w-full bg-transparent py-4 px-2 text-lg text-slate-100 focus:outline-none placeholder-slate-500"
              required
            />
            <button 
              type="submit" 
              :disabled="loading"
              class="bg-teal-500 hover:bg-teal-400 text-slate-900 font-bold py-4 px-8 transition-colors duration-200 flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <span v-if="!loading">Scan</span>
              <span v-else class="flex items-center gap-2">
                <svg class="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Scanning...
              </span>
            </button>
          </div>
        </form>
      </section>

      <!-- Error State -->
      <div v-if="error" class="max-w-3xl mx-auto p-4 mb-8 bg-rose-500/10 border border-rose-500/50 rounded-xl text-rose-400 flex items-start gap-3">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <div>
          <h3 class="font-bold">Scan Failed</h3>
          <p>{{ error }}</p>
        </div>
      </div>

      <!-- Results Dashboard -->
      <div v-if="results && !loading" class="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
        <!-- Target Info -->
        <div class="flex items-center justify-between p-6 bg-slate-800/50 rounded-2xl border border-slate-700">
          <div>
            <h3 class="text-sm font-medium text-slate-400">Target</h3>
            <p class="text-xl font-mono text-teal-300 mt-1">{{ results.target_url }}</p>
          </div>
          <div class="text-right">
            <h3 class="text-sm font-medium text-slate-400">Status</h3>
            <p class="text-xl font-semibold text-emerald-400 mt-1">Scan Complete</p>
          </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          <!-- HTTP Headers -->
          <div class="col-span-1 lg:col-span-2 space-y-4">
            <h3 class="text-2xl font-bold flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-teal-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
              </svg>
              HTTP Security Headers
            </h3>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div v-for="(data, header) in results.headers" :key="header" 
                class="p-5 rounded-xl border transition-colors"
                :class="data.status === 'PASS' ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-rose-500/10 border-rose-500/20'">
                <div class="flex justify-between items-start mb-2">
                  <span class="font-mono text-sm font-bold truncate" :class="data.status === 'PASS' ? 'text-emerald-300' : 'text-rose-300'">{{ header }}</span>
                  <span class="px-2 py-1 text-xs font-bold rounded-full" 
                        :class="data.status === 'PASS' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'">
                    {{ data.status }}
                  </span>
                </div>
                <p class="text-xs text-slate-400 leading-relaxed">{{ data.recommendation }}</p>
              </div>
            </div>
          </div>

          <!-- Network Banners -->
          <div class="space-y-4">
            <h3 class="text-2xl font-bold flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-indigo-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
              </svg>
              Open Ports
            </h3>
            <div class="bg-slate-800/50 rounded-xl border border-slate-700 overflow-hidden">
              <div v-if="!results.banners || results.banners.length === 0" class="p-6 text-center text-slate-500">
                No open ports detected.
              </div>
              <ul class="divide-y divide-slate-700/50">
                <li v-for="port in results.banners" :key="port.port" class="p-4 flex items-center justify-between">
                  <div class="flex items-center gap-3">
                    <div class="w-2 h-2 rounded-full bg-indigo-500 shadow-[0_0_8px_rgba(99,102,241,0.8)]"></div>
                    <div>
                      <p class="font-bold text-slate-200">Port {{ port.port }}</p>
                      <p class="text-xs text-slate-400 font-mono">{{ port.service || 'Unknown service' }}</p>
                    </div>
                  </div>
                  <span class="text-xs font-bold text-indigo-300 bg-indigo-500/20 px-2 py-1 rounded">OPEN</span>
                </li>
              </ul>
            </div>
          </div>

          <!-- Forms Compliance -->
          <div class="col-span-1 lg:col-span-3 space-y-4 mt-4">
            <h3 class="text-2xl font-bold flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-amber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Forms Compliance
            </h3>
            
            <div v-if="!results.forms || results.forms.length === 0" class="p-6 bg-slate-800/50 border border-slate-700 rounded-xl text-center text-slate-400">
              No HTML forms detected on the root page.
            </div>
            
            <div v-else class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div v-for="(form, idx) in results.forms" :key="idx" class="p-5 bg-slate-800/50 border border-slate-700 rounded-xl hover:border-slate-600 transition-colors">
                <div class="flex items-center justify-between mb-3">
                  <span class="font-mono text-sm bg-slate-900 px-2 py-1 rounded text-slate-300">Form #{{ form.form_index }}</span>
                  <span class="px-2 py-1 text-xs font-bold rounded"
                        :class="{
                          'bg-emerald-500/20 text-emerald-300': form.risk_level === 'LOW',
                          'bg-amber-500/20 text-amber-300': form.risk_level === 'MEDIUM',
                          'bg-rose-500/20 text-rose-300': form.risk_level === 'HIGH'
                        }">
                    {{ form.risk_level }} RISK
                  </span>
                </div>
                <div class="space-y-2 text-sm">
                  <p class="flex justify-between border-b border-slate-700/50 pb-1">
                    <span class="text-slate-400">Action:</span> 
                    <span class="font-mono text-slate-200 truncate max-w-[200px]">{{ form.action }}</span>
                  </p>
                  <p class="flex justify-between border-b border-slate-700/50 pb-1">
                    <span class="text-slate-400">Method:</span> 
                    <span class="font-mono text-slate-200">{{ form.method }}</span>
                  </p>
                  <p class="flex justify-between border-b border-slate-700/50 pb-1">
                    <span class="text-slate-400">CSRF Token:</span> 
                    <span :class="form.csrf_protection?.present ? 'text-emerald-400' : 'text-rose-400'">
                      {{ form.csrf_protection?.present ? 'Present' : 'Missing' }}
                    </span>
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
  </div>
</template>

<script setup>
import { ref } from 'vue'

const targetUrl = ref('')
const loading = ref(false)
const results = ref(null)
const error = ref(null)

const runScan = async () => {
  if (!targetUrl.value) return
  
  loading.value = true
  error.value = null
  results.value = null

  try {
    const res = await $fetch('http://localhost:8000/api/scan', {
      method: 'POST',
      body: { target_url: targetUrl.value },
      // Set a long timeout since banner grabbing can take up to 45s
      timeout: 60000 
    })
    results.value = res
  } catch (err) {
    error.value = err.data?.detail || err.message || 'An unknown error occurred during the scan.'
  } finally {
    loading.value = false
  }
}
</script>
