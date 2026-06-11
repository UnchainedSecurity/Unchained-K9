import React, { useState, useEffect, useRef, useMemo } from 'react'
import { Search, ShieldAlert, Radar, Loader2, Sparkles, Settings, ChevronDown, ChevronUp, XCircle, Bug, ChevronLeft, ChevronRight, Download, Filter, Camera, History, Menu, Clock, Info, Save, Folder, FolderOpen, FileCode, FileText, Database, File, Globe } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import AttackSurfaceMap from './components/AttackSurfaceMap'
import { SeverityBadge } from './components/SeverityBadge'
function escapeMarkdownCell(value) { return String(value ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').trim() }
function downloadBlob(filename, content, type) {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

function buildMarkdownReport(target, findings, technologies) {
  const safeTarget = target?.trim() || 'unknown'
  const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Info']
  let md = `# BlackHound K9 Security Report\n\n## Target Summary\n| Field | Value |\n| --- | --- |\n| **Targets** | \`${safeTarget}\` |\n| **Total Findings** | ${findings.length} |\n| **Date Generated** | ${new Date().toUTCString()} |\n\n`
  
  if (technologies && technologies.length > 0) {
    md += `## Infrastructure Profile\n| Category | Technology | Location |\n| --- | --- | --- |\n`
    for (const tech of technologies) {
      md += `| ${escapeMarkdownCell(tech.category)} | ${escapeMarkdownCell(tech.technology)} | \`${escapeMarkdownCell(tech.location)}\` |\n`
    }
    md += `\n`
  }

  for (const severity of severityOrder) {
    const group = findings.filter(f => (f.severity || 'Info') === severity)
    md += `## ${severity} Findings\n\n`
    if (group.length === 0) { md += `*No findings.*\n\n`; continue }
    md += `| Type | Value |\n| --- | --- |\n`
    for (const finding of group) md += `| ${escapeMarkdownCell(finding.type)} | \`${escapeMarkdownCell(finding.value)}\` |\n`
    md += `\n`
    md += `\n`
  }
  
  const filteredNoise = findings.filter(f => f.fp_reason)
  if (filteredNoise.length > 0) {
    const reasonCounts = {}
    filteredNoise.forEach(f => {
      reasonCounts[f.fp_reason] = (reasonCounts[f.fp_reason] || 0) + 1
    })
    md += `## Appendix: Filtered Noise\n\nK9 automatically filtered out the following False Positives:\n`
    for (const [reason, count] of Object.entries(reasonCounts)) {
      md += `- ${count}x ${escapeMarkdownCell(reason)}\n`
    }
    md += `\n`
  }
  
  return md
}



function RenderValue({ value }) {
  const safeVal = String(value || '')
  if (safeVal.startsWith('http://') || safeVal.startsWith('https://')) {
    return <a href={safeVal} target="_blank" rel="noreferrer" className="text-blue-400 hover:text-blue-300 hover:underline">{safeVal}</a>
  }
  return <span>{safeVal}</span>
}

const WORDLIST_OPTIONS = [
  { key: 'quick', label: 'Quick' },
  { key: 'directories', label: 'Directories' },
  { key: 'files', label: 'Files' },
  { key: 'apis', label: 'APIs' },
  { key: 'parameters', label: 'Parameters' },
  { key: 'backups', label: 'Backups' },
  { key: 'admin_panels', label: 'Admin Panels' },
  { key: 'cms', label: 'CMS' },
  { key: 'infrastructure', label: 'Infrastructure' }
]

export default function App() {
  const [legalAccepted, setLegalAccepted] = useState(true)
  const [legalInput, setLegalInput] = useState('')
  const [attackSurfaceTree, setAttackSurfaceTree] = useState([])
  const [selectedTreeNodeId, setSelectedTreeNodeId] = useState(null)

  const [targets, setTargets] = useState('')
  const [findings, setFindings] = useState([])
  const [technologies, setTechnologies] = useState([])
  const [aiAnalysis, setAiAnalysis] = useState('')
  const [activeTab, setActiveTab] = useState('vulnerabilities')
  const [status, setStatus] = useState('idle') 
  const [errorMsg, setErrorMsg] = useState('')
  const [showSettings, setShowSettings] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  
  const [showSidebar, setShowSidebar] = useState(false)
  const [historyList, setHistoryList] = useState([])
  const [currentScanId, setCurrentScanId] = useState(null)
  
  const [hideFalsePositives, setHideFalsePositives] = useState(true)
  
  const [noiseLevel, setNoiseLevel] = useState('Normal')
  const [customThreads, setCustomThreads] = useState(5)
  const [scanDepth, setScanDepth] = useState('Normal')
  const [customHeaders, setCustomHeaders] = useState('')
  const [proxyUrl, setProxyUrl] = useState('')
  const [webhookUrl, setWebhookUrl] = useState('')
  const [rateLimit, setRateLimit] = useState(150)
  const [apiUrl, setApiUrl] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [modelName, setModelName] = useState('')
  const [temperature, setTemperature] = useState(0.1)
  const [topK, setTopK] = useState(64)
  const [topP, setTopP] = useState(0.95)
  const [minP, setMinP] = useState(0.0)
  
  const [wordlistCategories, setWordlistCategories] = useState(['quick', 'backups', 'admin_panels'])
  const [screenshots, setScreenshots] = useState([])
  const [recursionDepth, setRecursionDepth] = useState(0)
  const [toggles, setToggles] = useState({ run_harvester: true, run_gau: true, run_katana: true, run_nuclei: true, run_dalfox: false, run_nucleidast: false, run_vhost: false, run_gowitness: true, run_favicon: true, run_js_secrets: false, run_cloud_enum: false })
  
  const [logs, setLogs] = useState([])
  const [errorLogs, setErrorLogs] = useState([])
  const [errorsOnly, setErrorsOnly] = useState(false)
  const [progress, setProgress] = useState({ percent: 0, label: '' })
  const [currentPage, setCurrentPage] = useState(1)
  const [sortBy, setSortBy] = useState('severity')
  const [exportMenuOpen, setExportMenuOpen] = useState(false)

  const terminalRef = useRef(null)
  const wsRef = useRef(null)
  const exportMenuRef = useRef(null)

  const [profiles, setProfiles] = useState([])
  const [expandedGroups, setExpandedGroups] = useState({})

  const toggleWordlist = (key) => {
    setWordlistCategories(prev => 
      prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
    )
  }

  const loadProfiles = async () => {
    try {
      const res = await fetch('http://localhost:8000/profiles')
      setProfiles(await res.json())
    } catch(e) {}
  }

  const applyProfile = (configStr) => {
    try {
      const conf = JSON.parse(configStr)
      if (conf.customThreads !== undefined) setCustomThreads(conf.customThreads)
      if (conf.rateLimit !== undefined) setRateLimit(conf.rateLimit)
      if (conf.toggles) setToggles(conf.toggles)
      if (conf.wordlistCategories) setWordlistCategories(conf.wordlistCategories)
      if (conf.recursionDepth !== undefined) setRecursionDepth(conf.recursionDepth)
      if (conf.apiUrl !== undefined) setApiUrl(conf.apiUrl)
      if (conf.apiKey !== undefined) setApiKey(conf.apiKey)
      if (conf.modelName !== undefined) setModelName(conf.modelName)
      if (conf.temperature !== undefined) setTemperature(conf.temperature)
      if (conf.topK !== undefined) setTopK(conf.topK)
      if (conf.topP !== undefined) setTopP(conf.topP)
      if (conf.minP !== undefined) setMinP(conf.minP)
      if (conf.webhookUrl !== undefined) setWebhookUrl(conf.webhookUrl)
    } catch(e) {}
  }

  const saveNewProfile = async () => {
    const name = prompt("Enter a name for this profile:")
    if (!name) return
    const config_json = JSON.stringify({
      customThreads, rateLimit, toggles, wordlistCategories, recursionDepth,
      apiUrl, apiKey, modelName, temperature, topK, topP, minP, webhookUrl
    })
    try {
      await fetch('http://localhost:8000/profiles', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, config_json })
      })
      await loadProfiles()
    } catch(e) {
      alert("Failed to save profile")
    }
  }

  const loadHistory = async () => {
    try {
      const res = await fetch('http://localhost:8000/history')
      setHistoryList(await res.json())
    } catch(e) {}
  }

  const loadScan = async (scanId = null) => {
    try {
      const url = scanId ? `http://localhost:8000/history/${scanId}` : 'http://localhost:8000/results'
      const res = await fetch(url)
      const data = await res.json()
      if (data.stage === 'completed' && (data.findings?.length > 0 || data.technologies?.length > 0)) {
        setFindings(data.findings || [])
        setTechnologies(data.technologies || [])
        setAiAnalysis(data.ai_analysis || '')
        setScreenshots(data.screenshots || [])
        setTargets(data.target || '')
        if (data.scan_id) setCurrentScanId(data.scan_id)
        setStatus('completed')
        setProgress({ percent: 100, label: 'Loaded Previous Scan Data' })
        
        try {
           const tUrl = scanId ? `http://localhost:8000/history/${scanId}/attack-surface` : 'http://localhost:8000/attack-surface'
           const tRes = await fetch(tUrl)
           const tData = await tRes.json()
           setAttackSurfaceTree(JSON.parse(tData.tree || '[]'))
        } catch(e) {
           setAttackSurfaceTree([])
        }
      }
    } catch(e) {}
  }

  useEffect(() => {
    if (!localStorage.getItem('k9_legal_accepted')) setLegalAccepted(false)
    loadHistory()
    loadScan()
    loadProfiles()
  }, [])

  const acceptLegal = () => {
    if (legalInput === 'I AGREE') {
      localStorage.setItem('k9_legal_accepted', 'true')
      setLegalAccepted(true)
    }
  }

  useEffect(() => {
    wsRef.current = new WebSocket('ws://localhost:8000/ws/logs')
    wsRef.current.onmessage = async (e) => {
      const msg = e.data
      if (msg.startsWith('[PROGRESS]')) {
        const match = msg.match(/\[PROGRESS\] (\d+)\/(\d+): (.*)/)
        if (match) setProgress({ percent: Math.round((parseInt(match[1]) / parseInt(match[2])) * 100), label: match[3] })
        return
      }
      if (msg === "[HUNT:COMPLETED]") {
        await loadHistory()
        await loadScan()
        return
      }
      
      if (msg === "[HUNT:BATCH_COMPLETED]") {
        try {
          const res = await fetch('http://localhost:8000/results')
          const data = await res.json()
          if (data.findings) setFindings(data.findings)
          if (data.technologies) setTechnologies(data.technologies)
          if (data.screenshots) setScreenshots(data.screenshots)
        } catch (err) {}
        return
      }

      if (msg.startsWith("[AI_STREAM]")) {
        setAiAnalysis(prev => prev + msg.replace("[AI_STREAM]", ""))
        return
      }

      const isError = /\[!\]|error|failed|\[stats\]/i.test(msg);
      if (isError) setErrorLogs(prev => [...prev, msg]);
      setLogs(prev => [...prev, msg].slice(-1000))
    }
    return () => { if (wsRef.current) wsRef.current.close() }
  }, [])

  useEffect(() => {
    if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight
  }, [logs, errorsOnly])

  useEffect(() => {
    function handleClickOutside(event) {
      if (exportMenuRef.current && !exportMenuRef.current.contains(event.target)) setExportMenuOpen(false)
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const severityCounts = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0, Unknown: 0 }
    findings.forEach(f => { const sev = f.severity || 'Info'; if (counts[sev] !== undefined) counts[sev]++ })
    return counts
  }, [findings])

  const filteredFindings = useMemo(() => {
    let filtered = findings
    if (hideFalsePositives) {
      filtered = filtered.filter(f => f.status !== 'False Positive' && !String(f.type).includes('[FP]'))
    }
    return filtered
  }, [findings, hideFalsePositives])

  const searchedFindings = useMemo(() => {
    if (!searchTerm) return filteredFindings
    return filteredFindings.filter(f => String(f.value).toLowerCase().includes(searchTerm.toLowerCase()) || String(f.type).toLowerCase().includes(searchTerm.toLowerCase()))
  }, [filteredFindings, searchTerm])

  const sortedFindings = useMemo(() => {
    if (sortBy === 'original') return searchedFindings
    const weights = { Critical: 6, High: 5, Medium: 4, Low: 3, Info: 2, Unknown: 1 }
    return [...searchedFindings].sort((a, b) => (weights[b.severity] || 1) - (weights[a.severity] || 1))
  }, [searchedFindings, sortBy])



  const ITEMS_PER_PAGE = 50
  const totalPages = Math.max(1, Math.ceil(sortedFindings.length / ITEMS_PER_PAGE))
  const paginatedFindings = useMemo(() => {
    const start = (currentPage - 1) * ITEMS_PER_PAGE
    return sortedFindings.slice(start, start + ITEMS_PER_PAGE)
  }, [sortedFindings, currentPage])


  useEffect(() => { setCurrentPage(1) }, [sortBy, searchTerm, findings])

  const startRecon = async (e) => {
    e.preventDefault()
    if (!targets.trim()) return
    setStatus('scanning')
    setErrorMsg('')
    setFindings([])
    setTechnologies([])
    setScreenshots([])
    setAiAnalysis('')
    setLogs([])
    setErrorLogs([])
    setProgress({ percent: 0, label: 'Initializing Pipeline...' })

    let finalThreads = 50
    if (noiseLevel === 'Stealth') finalThreads = 10
    else if (noiseLevel === 'Loud') finalThreads = 100
    else if (noiseLevel === 'Custom') finalThreads = parseInt(customThreads)

    const targetsList = targets.split('\n').map(t => t.trim()).filter(t => t.length > 0)
    const headersList = customHeaders.split('\n').map(h => h.trim()).filter(h => h.length > 0)

    try {
      const res = await fetch('http://localhost:8000/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          targets: targetsList, threads: finalThreads, scan_depth: scanDepth, 
          custom_headers: headersList, proxy_url: proxyUrl.trim(), webhook_url: webhookUrl.trim(),
          rate_limit: parseInt(rateLimit),
          api_url: apiUrl, api_key: apiKey, model_name: modelName,
          temperature: parseFloat(temperature), top_k: parseInt(topK), top_p: parseFloat(topP), min_p: parseFloat(minP),
          wordlist: wordlistCategories,
          toggles: { ...toggles, recursion_depth: recursionDepth }
        })
      })
      if (!res.ok) {
        if (res.status === 409) throw new Error('A scan is already in progress. Cancel it first.')
        throw new Error('Backend API rejected the request.')
      }
    } catch (err) {
      setStatus('error')
      setErrorMsg(err.message || 'Failed to connect to backend.')
    }
  }

  const cancelScan = async () => {
    try {
      await fetch('http://localhost:8000/cancel', { method: 'POST' })
      setStatus('idle')
      setProgress({ percent: 0, label: 'Scan Cancelled' })
    } catch (err) {}
  }

  const handleExportJson = () => {
    const importantFindings = sortedFindings.filter(f => f.severity !== 'Info' && f.severity !== 'Low')
    const payload = JSON.stringify({ infrastructure: technologies, vulnerabilities: importantFindings }, null, 2)
    const safeTarget = 'report'
    downloadBlob(`K9_${safeTarget}_findings.json`, payload, 'application/json;charset=utf-8')
    setExportMenuOpen(false)
  }

  const handleExportMarkdown = () => {
    const importantFindings = sortedFindings.filter(f => f.severity !== 'Info' && f.severity !== 'Low')
    const md = buildMarkdownReport(targets, importantFindings, technologies)
    const safeTarget = 'report'
    downloadBlob(`K9_${safeTarget}_report.md`, md, 'text/markdown;charset=utf-8')
    setExportMenuOpen(false)
  }

  if (!legalAccepted) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-950 p-4">
        <div className="bg-gray-900 border border-red-500/50 rounded-2xl p-8 max-w-lg shadow-2xl text-center">
          <ShieldAlert className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-white mb-2">Legal Disclaimer</h1>
          <p className="text-sm text-slate-300 mb-6 leading-relaxed">
            BlackHound K9 is an offensive security tool designed STRICTLY for authorized bug bounty hunting. 
            Running these tools against targets without explicit permission is illegal. By continuing, you accept full responsibility.
          </p>
          <input type="text" value={legalInput} onChange={e=>setLegalInput(e.target.value)} placeholder="Type 'I AGREE' to continue" className="w-full bg-black border border-gray-700 rounded-lg px-4 py-3 text-white text-center mb-4 uppercase" />
          <button onClick={acceptLegal} disabled={legalInput !== 'I AGREE'} className="w-full bg-red-600 hover:bg-red-500 text-white font-bold py-3 rounded-lg disabled:opacity-50 transition">Accept &amp; Enter</button>
        </div>
      </div>
    )
  }

  const displayLogs = errorsOnly ? errorLogs : logs;

  const updateStatus = async (id, newStatus) => {
    try {
      await fetch(`http://localhost:8000/findings/${id}/status`, {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({status: newStatus})
      })
      setFindings(prev => prev.map(f => f.id === id ? {...f, status: newStatus} : f))
    } catch (e) {}
  }

  return (
    <div className="min-h-full bg-[radial-gradient(circle_at_top,_rgba(185,28,28,0.12),_transparent_35%),linear-gradient(to_bottom,#020617,#030712_45%,#020617)] text-red-500">
      <div className={`mx-auto flex min-h-screen w-full ${showSidebar ? 'max-w-[90rem] gap-6 flex-row' : 'max-w-6xl flex-col'} px-4 py-8 transition-all duration-300`}>
        {showSidebar && (
          <aside className="w-72 shrink-0 flex flex-col gap-4">
            <div className="rounded-3xl border border-white/10 bg-white/5 p-4 shadow-2xl backdrop-blur-xl h-full flex flex-col">
              <div className="flex items-center gap-2 text-white font-semibold mb-4 border-b border-white/10 pb-4">
                <History className="w-5 h-5 text-red-500" /> Scan History
              </div>
              <div className="flex-1 overflow-y-auto pr-2 space-y-2">
                {historyList.length === 0 ? <div className="text-sm text-slate-500">No past scans found.</div> : historyList.map(h => (
                  <button key={h.id} onClick={() => loadScan(h.id)} className={`w-full text-left p-3 rounded-xl border transition ${currentScanId === h.id ? 'bg-red-500/20 border-red-500/50 text-white' : 'bg-black/40 border-white/5 text-slate-300 hover:bg-white/10 hover:border-white/20'}`}>
                    <div className="font-semibold text-sm truncate">{h.targets}</div>
                    <div className="text-xs text-slate-500 mt-1 flex items-center gap-1"><Clock className="w-3 h-3" /> {new Date(h.timestamp).toLocaleString()}</div>
                  </button>
                ))}
              </div>
            </div>
          </aside>
        )}
        <div className="flex-1 flex flex-col min-w-0">
        
        <header className="mb-6 rounded-3xl border border-white/10 bg-white/5 p-6 shadow-2xl backdrop-blur-xl flex justify-between items-center">
          <div className="flex items-center gap-4">
            <button onClick={() => setShowSidebar(!showSidebar)} className="p-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 transition text-slate-300">
              <Menu className="w-5 h-5" />
            </button>
            <div>
              <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-red-600/30 bg-red-700/10 px-3 py-1 text-xs font-medium text-red-400">
                <Sparkles className="h-3.5 w-3.5" /> BLACKHOUND K9 PRO <span className="text-slate-500">v3.14</span>
              </div>
              <h1 className="text-3xl font-semibold text-white">Recon Dashboard</h1>
            </div>
          </div>
          <div className="flex gap-3">
            <div className="rounded-2xl border border-white/10 bg-black/40 px-5 py-3">
              <div className="text-xs uppercase text-slate-500">Status</div>
              <div className="mt-1 text-sm font-medium text-white capitalize">{status}</div>
            </div>
          </div>
        </header>

        <section className="mb-6 rounded-3xl border border-white/10 bg-white/5 shadow-2xl backdrop-blur-xl overflow-hidden">
          <button onClick={() => setShowSettings(!showSettings)} className="w-full p-4 flex items-center justify-between hover:bg-white/5 transition">
            <div className="flex items-center gap-2 text-red-500"><Settings className="w-5 h-5" /><span className="font-semibold">Advanced Config &amp; AI Tuning</span></div>
            {showSettings ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
          </button>
          {showSettings && (
            <div className="p-6 border-t border-white/10">
              <div className="flex items-center gap-4 mb-6 pb-4 border-b border-white/5">
                <div className="flex-1">
                  <label className="block text-xs font-semibold text-slate-400 mb-2 uppercase">Load Config Profile</label>
                  <select onChange={(e) => applyProfile(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2 text-white outline-none">
                    <option value="">-- Select a Profile --</option>
                    {profiles.map(p => (
                      <option key={p.id} value={p.config_json}>{p.name}</option>
                    ))}
                  </select>
                </div>
                <div className="pt-6">
                  <button onClick={saveNewProfile} className="px-4 py-2 bg-red-600/20 text-red-400 border border-red-600/30 rounded-xl hover:bg-red-600/30 transition text-sm font-medium flex items-center gap-2">
                    <Save className="w-4 h-4" /> Save as New Profile
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Noise Level</label>
                  <select value={noiseLevel} onChange={(e) => setNoiseLevel(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2 text-white outline-none">
                    <option value="Stealth">Stealth (10 Threads)</option>
                    <option value="Normal">Normal (50 Threads)</option>
                    <option value="Loud">Loud (100 Threads)</option>
                    <option value="Custom">Custom</option>
                  </select>
                  {noiseLevel === 'Custom' && (
                    <div className="mt-2">
                      <label className="block text-xs text-slate-400 mb-1">Custom Threads</label>
                      <input type="number" min="1" value={customThreads} onChange={(e) => setCustomThreads(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2 text-white outline-none" />
                    </div>
                  )}
                </div>
                <div><label className="block text-xs text-slate-400 mb-1">Scan Depth (Nuclei)</label><select value={scanDepth} onChange={(e) => setScanDepth(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2 text-white outline-none"><option value="Sniper">Sniper (Fast - High/Crit)</option><option value="Normal">Normal (Balanced)</option><option value="Carpet Bomb">Carpet Bomb (Slow - All)</option></select></div>
                <div><label className="block text-xs text-slate-400 mb-1">Rate Limit (Req/s)</label><input type="number" value={rateLimit} onChange={(e) => setRateLimit(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2 text-white outline-none" min="1" /></div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Custom Headers (One per line)</label>
                  <textarea value={customHeaders} onChange={(e) => setCustomHeaders(e.target.value)} placeholder={"Authorization: Bearer xyz\nCookie: session=123"} rows="3" className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2 text-white placeholder-slate-600 outline-none resize-none"></textarea>
                </div>
                <div className="flex flex-col gap-4">
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Burp Proxy URL</label>
                    <input type="text" value={proxyUrl} onChange={(e) => setProxyUrl(e.target.value)} placeholder="e.g. http://host.docker.internal:8080" className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2 text-white placeholder-slate-600 outline-none" />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Webhook URL (Slack/Discord)</label>
                    <input type="text" value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} placeholder="https://discord.com/api/webhooks/..." className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2 text-white placeholder-slate-600 outline-none" />
                  </div>
                </div>
              </div>

              <div className="border-t border-white/10 pt-4 mt-2 mb-4">
                <h3 className="text-xs font-semibold text-red-500 mb-3 uppercase">Payload Compiler (Wordlists)</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {WORDLIST_OPTIONS.map(opt => (
                    <label key={opt.key} className="flex items-center gap-2 text-sm text-slate-300 bg-black/30 border border-white/10 rounded-lg px-3 py-2 hover:bg-white/5 transition cursor-pointer">
                      <input type="checkbox" checked={wordlistCategories.includes(opt.key)} onChange={() => toggleWordlist(opt.key)} className="accent-red-500" />
                      {opt.label}
                    </label>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Recursion Depth (ffuf)</label>
                  <input type="number" min="0" value={recursionDepth} onChange={(e) => setRecursionDepth(parseInt(e.target.value) || 0)} className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2 text-white outline-none" />
                  {recursionDepth > 0 && (
                    <p className="mt-1.5 text-xs text-yellow-400">⚠ Warning: Recursion multiplies requests exponentially and will drastically increase scan time.</p>
                  )}
                </div>
              </div>

              <div className="border-t border-white/10 pt-4 mt-2 mb-4">
                <label className="block text-xs text-slate-400 mb-2">Tool Toggles</label>
                <div className="flex flex-wrap gap-4">
                  <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={toggles.run_harvester} onChange={e=>setToggles({...toggles, run_harvester: e.target.checked})} /> theHarvester</label>
                  <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={toggles.run_gau} onChange={e=>setToggles({...toggles, run_gau: e.target.checked})} /> GAU</label>
                  <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={toggles.run_katana} onChange={e=>setToggles({...toggles, run_katana: e.target.checked})} /> Katana</label>
                  <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={toggles.run_nuclei} onChange={e=>setToggles({...toggles, run_nuclei: e.target.checked})} /> Nuclei</label>
                  <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={toggles.run_dalfox} onChange={e=>setToggles({...toggles, run_dalfox: e.target.checked})} /> Dalfox (XSS)</label>
                  <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={toggles.run_nucleidast} onChange={e=>setToggles({...toggles, run_nucleidast: e.target.checked})} /> Nuclei DAST (SQLi/Redirect)</label>
                  <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={toggles.run_vhost} onChange={e=>setToggles({...toggles, run_vhost: e.target.checked})} /> VHost Discovery</label>
                  <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={toggles.run_gowitness} onChange={e=>setToggles({...toggles, run_gowitness: e.target.checked})} /> Gowitness (Screenshots)</label>
                  <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={toggles.run_favicon} onChange={e=>setToggles({...toggles, run_favicon: e.target.checked})} /> Favicon Hashing</label>
                  <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={toggles.run_js_secrets} onChange={e=>setToggles({...toggles, run_js_secrets: e.target.checked})} /> JS Secret Hunting</label>
                  <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={toggles.run_cloud_enum} onChange={e=>setToggles({...toggles, run_cloud_enum: e.target.checked})} /> Cloud Asset Discovery</label>
                </div>
              </div>

              <div className="border-t border-white/10 pt-4 mt-2">
                <div className="flex justify-between items-center mb-3">
                  <h3 className="text-xs font-semibold text-red-500 uppercase">AI Engine Settings</h3>
                  <button onClick={() => { setTemperature(0.2); setTopP(0.95); setTopK(40); setMinP(0.0); }} className="text-xs flex items-center gap-1 bg-red-900/30 text-red-400 hover:bg-red-900/50 border border-red-700/50 px-2 py-1 rounded transition">
                    🛡️ Recommended Security AI Settings
                  </button>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                  <div className="md:col-span-2"><label className="block text-xs text-slate-400 mb-1">API URL</label><input type="text" value={apiUrl} onChange={(e) => setApiUrl(e.target.value)} placeholder="e.g. https://openrouter.ai/api/v1" className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2 text-white outline-none" /></div>
                  <div className="md:col-span-2"><label className="block text-xs text-slate-400 mb-1">API Key</label><input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="sk-..." className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2 text-white outline-none" /></div>
                  <div className="md:col-span-4"><label className="block text-xs text-slate-400 mb-1">Model Name</label><input type="text" value={modelName} onChange={(e) => setModelName(e.target.value)} placeholder="Default: OS Env Var" className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2 text-white outline-none" /></div>
                  <div><label className="flex items-center gap-1 text-xs text-slate-400 mb-1 group relative">Temp <Info className="w-3 h-3 text-slate-500 cursor-help" /><span className="absolute bottom-full mb-1 hidden group-hover:block w-48 bg-gray-900 text-gray-200 text-[10px] p-2 rounded shadow-lg border border-white/10 z-10">Controls creativity. Keep LOW (0.1 - 0.3) for security triage to prevent hallucinations.</span></label><input type="number" step="0.1" value={temperature} onChange={(e) => setTemperature(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-1.5 text-white" /></div>
                  <div><label className="flex items-center gap-1 text-xs text-slate-400 mb-1 group relative">Top K <Info className="w-3 h-3 text-slate-500 cursor-help" /><span className="absolute bottom-full mb-1 hidden group-hover:block w-48 bg-gray-900 text-gray-200 text-[10px] p-2 rounded shadow-lg border border-white/10 z-10">Limits vocabulary pool. Keep ~40 to focus the LLM on high-probability technical terms.</span></label><input type="number" step="1" value={topK} onChange={(e) => setTopK(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-1.5 text-white" /></div>
                  <div><label className="flex items-center gap-1 text-xs text-slate-400 mb-1 group relative">Top P <Info className="w-3 h-3 text-slate-500 cursor-help" /><span className="absolute bottom-full mb-1 hidden group-hover:block w-48 bg-gray-900 text-gray-200 text-[10px] p-2 rounded shadow-lg border border-white/10 z-10">Dynamic vocabulary threshold. 0.95 allows slightly technical variations without degrading logic.</span></label><input type="number" step="0.05" value={topP} onChange={(e) => setTopP(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-1.5 text-white" /></div>
                  <div><label className="flex items-center gap-1 text-xs text-slate-400 mb-1 group relative">Min P <Info className="w-3 h-3 text-slate-500 cursor-help" /><span className="absolute bottom-full mb-1 hidden group-hover:block w-48 bg-gray-900 text-gray-200 text-[10px] p-2 rounded shadow-lg border border-white/10 z-10">Filters out low probability tokens. 0.05 or 0.1 stops rambling.</span></label><input type="number" step="0.05" value={minP} onChange={(e) => setMinP(e.target.value)} className="w-full bg-black/50 border border-white/10 rounded-xl px-3 py-1.5 text-white" /></div>
                </div>
              </div>
            </div>
          )}
        </section>

        <form onSubmit={startRecon} className="mb-6 flex flex-col md:flex-row gap-4 rounded-3xl border border-white/10 bg-white/5 p-6 shadow-2xl backdrop-blur-xl">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-4 w-5 h-5 text-slate-500" />
            <textarea value={targets} onChange={(e) => setTargets(e.target.value)} placeholder="Enter target domains (one per line)" rows="3" className="w-full rounded-2xl border border-white/10 bg-slate-950/80 pl-12 pr-4 py-4 text-white outline-none focus:border-red-600/50 resize-none" disabled={status === 'scanning'}></textarea>
          </div>
          <div className="flex gap-2">
            <button type="submit" disabled={status === 'scanning' || !targets.trim()} className="flex h-full items-center justify-center gap-2 rounded-2xl bg-red-700 px-6 py-4 font-semibold text-slate-950 hover:bg-red-600 disabled:opacity-50 transition">
              {status === 'scanning' ? <Loader2 className="h-5 w-5 animate-spin" /> : <Radar className="h-5 w-5" />} {status === 'scanning' ? 'Scanning' : 'Start Recon'}
            </button>
            {status === 'scanning' && (
              <button type="button" onClick={cancelScan} className="flex h-full items-center justify-center gap-2 rounded-2xl bg-blue-500/10 border border-blue-500/30 px-6 py-4 font-semibold text-blue-400 hover:bg-blue-500/20 transition">
                <XCircle className="h-5 w-5" /> Cancel
              </button>
            )}
          </div>
        </form>

        {(status === 'scanning' || progress.percent > 0) && (
          <div className="mb-6 rounded-2xl border border-white/10 bg-black/40 p-4">
            <div className="flex justify-between text-xs text-slate-300 mb-2">
              <span>{progress.label}</span>
              <span>{progress.percent}%</span>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-2.5">
              <div className="bg-red-700 h-2.5 rounded-full transition-all duration-500" style={{ width: `${progress.percent}%` }}></div>
            </div>
          </div>
        )}

        {status === 'error' && (
          <div className="mb-6 rounded-2xl border border-slate-500/30 bg-slate-500/10 p-4 flex items-center gap-3 text-slate-300">
            <XCircle className="w-5 h-5" /> <span className="text-sm font-medium">{errorMsg}</span>
          </div>
        )}

        <section className="mb-6 rounded-3xl border border-white/10 bg-black/80 shadow-2xl overflow-hidden flex flex-col h-64">
          <div className="bg-white/5 px-4 py-3 border-b border-white/10 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="flex gap-1.5"><div className="w-3 h-3 rounded-full bg-red-500/80"></div><div className="w-3 h-3 rounded-full bg-yellow-500/80"></div><div className="w-3 h-3 rounded-full bg-green-500/80"></div></div>
              <span className="text-xs text-slate-400 font-mono ml-2">k9_live_stream.sh</span>
            </div>
            <button type="button" onClick={() => setErrorsOnly(!errorsOnly)} className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded transition ${errorsOnly ? 'bg-red-500/20 text-red-400 border border-red-500/50' : 'bg-white/10 text-slate-400 border border-white/10'}`}>
              <Bug className="w-3 h-3" /> Errors Only
            </button>
          </div>
          <div ref={terminalRef} className="flex-1 p-4 overflow-y-auto font-mono text-sm leading-relaxed">
            {displayLogs.length === 0 ? <p className="text-slate-600">Awaiting stream...</p> : displayLogs.map((log, i) => (
              <div key={i} className={log.startsWith('>') ? 'text-blue-400 font-bold mt-2' : log.startsWith('[+]') ? 'text-green-400' : log.startsWith('[!]') ? 'text-red-400' : 'text-slate-300'}>{log}</div>
            ))}
          </div>
        </section>

        <div className="flex flex-wrap items-center gap-6 border-b border-white/10 mb-6 px-4">
          <button type="button" onClick={() => setActiveTab('vulnerabilities')} className={`pb-3 text-sm font-semibold transition-colors ${activeTab === 'vulnerabilities' ? 'text-red-500 border-b-2 border-red-500' : 'text-slate-400 hover:text-slate-200'}`}>Vulnerabilities</button>
          <button type="button" onClick={() => setActiveTab('map')} className={`pb-3 flex items-center gap-1 text-sm font-semibold transition-colors ${activeTab === 'map' ? 'text-green-400 border-b-2 border-green-400' : 'text-slate-400 hover:text-slate-200'}`}><Globe className="w-4 h-4" />Attack Surface Map</button>
          <button type="button" onClick={() => setActiveTab('infrastructure')} className={`pb-3 text-sm font-semibold transition-colors ${activeTab === 'infrastructure' ? 'text-cyan-400 border-b-2 border-cyan-400' : 'text-slate-400 hover:text-slate-200'}`}>Infrastructure Profile</button>
          <button type="button" onClick={() => setActiveTab('analysis')} className={`pb-3 text-sm font-semibold transition-colors ${activeTab === 'analysis' ? 'text-purple-400 border-b-2 border-purple-400' : 'text-slate-400 hover:text-slate-200'}`}>Executive AI Assessment</button>
          <button type="button" onClick={() => setActiveTab('gallery')} className={`pb-3 text-sm font-semibold transition-colors ${activeTab === 'gallery' ? 'text-red-500 border-b-2 border-red-500' : 'text-slate-400 hover:text-slate-200'}`}>Screenshot Gallery</button>
        </div>

        {activeTab === 'map' && (
          <div className="mb-6">
            <AttackSurfaceMap data={attackSurfaceTree} selectedNodeId={selectedTreeNodeId} />
          </div>
        )}

        {activeTab === 'infrastructure' && (
          <div className="mb-6 rounded-3xl border border-white/10 bg-white/5 p-6 shadow-2xl backdrop-blur-xl overflow-hidden">
            <div className="mb-4 flex items-center gap-3">
              <Radar className="h-5 w-5 text-cyan-400" />
              <h2 className="text-lg font-semibold text-white">Infrastructure Profile</h2>
            </div>
            {technologies.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {technologies.map((t, i) => (
                  <div key={i} className="rounded-xl border border-white/10 bg-black/40 p-4 hover:bg-white/5 transition border-l-2 border-l-cyan-500/50">
                    <div className="text-xs font-semibold text-cyan-400 mb-1 uppercase">{t.category}</div>
                    <div className="text-sm font-medium text-white break-words">{t.technology}</div>
                    <div className="mt-2 text-xs font-mono text-slate-400 break-all"><RenderValue value={t.location} /></div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-16 text-slate-500">
                No infrastructure data available.
              </div>
            )}
          </div>
        )}

        {activeTab === 'gallery' && (
          <div className="mb-6 rounded-3xl border border-white/10 bg-white/5 p-6 shadow-2xl backdrop-blur-xl overflow-hidden">
            <div className="mb-4 flex items-center gap-3">
              <Camera className="h-5 w-5 text-red-500" />
              <h2 className="text-lg font-semibold text-white">Screenshot Gallery</h2>
            </div>
            {screenshots.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {screenshots.map((img, i) => {
                  const rawUrl = img.replace(/\.png$/, '').replace(/^http-/, 'http://').replace(/^https-/, 'https://')
                  return (
                    <div key={i} className="rounded-xl border border-red-500/30 bg-black/40 overflow-hidden hover:border-red-500/80 transition shadow-lg">
                      <img src={`http://localhost:8000/screenshots/${img}`} alt={rawUrl} className="w-full object-cover" />
                      <div className="p-3 bg-white/5 border-t border-white/10 text-center">
                        <a href={rawUrl} target="_blank" rel="noreferrer" className="text-xs font-mono text-white hover:text-red-400 transition break-all">
                          {rawUrl}
                        </a>
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <div className="text-center py-16 text-slate-500">
                No screenshots available. Run a scan with Gowitness enabled.
              </div>
            )}
          </div>
        )}

        {activeTab === 'vulnerabilities' && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 shadow-2xl backdrop-blur-xl overflow-hidden">
            <div className="mb-6 flex flex-col xl:flex-row xl:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <ShieldAlert className="h-5 w-5 text-red-500" />
                <h2 className="text-lg font-semibold text-white">Vulnerability Findings</h2>
              </div>
              
              {findings.length > 0 && (
                <div className="flex flex-wrap items-center gap-4">
                  <div className="flex gap-2">
                    {['Critical','High','Medium','Low','Info'].map(sev => <span key={sev} className={`px-2 py-1 rounded-md text-xs font-semibold border ${severityCounts[sev] > 0 ? 'bg-white/10 border-white/20 text-white' : 'bg-transparent border-white/5 text-slate-600'}`}>{sev}: {severityCounts[sev]}</span>)}
                  </div>
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input type="text" value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} placeholder="Search findings..." className="bg-black/40 border border-white/10 rounded-xl pl-9 pr-3 py-1.5 text-sm text-white outline-none w-48 focus:border-red-600/50" />
                  </div>
                  <div className="flex items-center gap-2 bg-black/40 rounded-xl px-3 py-1.5 border border-white/10">
                    <label className="flex items-center gap-2 cursor-pointer text-sm text-slate-300">
                      <input type="checkbox" checked={hideFalsePositives} onChange={(e) => setHideFalsePositives(e.target.checked)} className="form-checkbox text-red-500 rounded border-white/20 bg-black/50" />
                      Hide FP
                    </label>
                  </div>
                  <div className="flex items-center gap-2 bg-black/40 rounded-xl px-3 py-1.5 border border-white/10">
                    <Filter className="w-4 h-4 text-slate-400" />
                    <select value={sortBy} onChange={(e) => setSortBy(e.target.value)} className="bg-transparent text-sm text-slate-200 outline-none">
                      <option value="severity">Sort: Severity</option>
                      <option value="original">Sort: Default</option>
                    </select>
                  </div>
                  <div className="relative" ref={exportMenuRef}>
                    <button type="button" onClick={() => setExportMenuOpen(!exportMenuOpen)} className="flex items-center gap-2 rounded-xl bg-white/10 border border-white/20 px-4 py-1.5 text-sm font-semibold text-white hover:bg-white/20">
                      <Download className="w-4 h-4" /> Export
                    </button>
                    {exportMenuOpen && (
                      <div className="absolute right-0 top-full mt-2 w-48 rounded-xl border border-white/10 bg-slate-900 shadow-xl overflow-hidden z-50">
                        <button type="button" onClick={handleExportJson} className="w-full text-left px-4 py-3 text-sm text-white hover:bg-white/10 border-b border-white/5">Export JSON (Raw)</button>
                        <button type="button" onClick={handleExportMarkdown} className="w-full text-left px-4 py-3 text-sm text-white hover:bg-white/10">Export Markdown</button>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="overflow-x-auto rounded-2xl border border-white/10 bg-black/40 mb-4">
              {paginatedFindings.length === 0 ? (
                <div className="px-4 py-16 text-center text-slate-500">
                  <Radar className={`w-12 h-12 mx-auto mb-4 ${status === 'scanning' ? 'animate-pulse text-red-600/50' : 'opacity-30'}`} />
                  {status === 'scanning' ? 'Reconnaissance in progress...' : searchTerm ? 'No findings match your search.' : 'No findings yet. Enter a target.'}
                </div>
              ) : (
                <table className="w-full text-left">
                  <thead>
                    <tr className="border-b border-white/10 bg-white/5 text-xs uppercase text-slate-400">
                      <th className="px-6 py-4">Type</th><th className="px-6 py-4">Value</th><th className="px-6 py-4">Severity</th><th className="px-6 py-4">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {paginatedFindings.map((f, i) => {
                      return (
                      <tr key={f.id || i} className={`hover:bg-white/5 transition-colors ${f.isChild ? 'bg-black/20' : ''}`}>
                        <td className={`px-6 py-4 text-sm font-medium text-white ${f.isChild ? 'pl-12 border-l-2 border-l-slate-700/50' : ''}`}>
                          <div className="flex items-center gap-2">
                            {f.type}
                            {f.fp_reason && (
                              <div className="relative group cursor-help">
                                <Info className="w-4 h-4 text-slate-400 hover:text-cyan-400 transition" />
                                <div className="absolute left-full ml-2 top-1/2 -translate-y-1/2 w-48 p-2 bg-slate-800 text-xs text-slate-200 rounded border border-white/10 opacity-0 group-hover:opacity-100 transition pointer-events-none z-10 shadow-xl whitespace-normal break-words">
                                  {f.fp_reason}
                                </div>
                              </div>
                            )}
                            {f.is_new && <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-600/20 text-red-400 border border-red-500/30 shadow-[0_0_8px_rgba(220,38,38,0.4)] animate-pulse">NEW</span>}
                          </div>
                        </td>
                        <td className="px-6 py-4 text-sm font-mono break-all">
                          <div className="flex items-center justify-between gap-2">
                            <RenderValue value={f.value} />
                            {f.value && (
                              <button 
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setActiveTab('map');
                                  setSelectedTreeNodeId(f.value.startsWith('http') ? f.value : `http://${f.value}`);
                                }}
                                className="shrink-0 px-2 py-1 rounded bg-black/40 border border-white/10 hover:bg-white/10 hover:text-white text-slate-400 text-[10px] uppercase font-bold flex items-center gap-1 transition"
                                title="View in Attack Surface Map"
                              >
                                🗺️ Map
                              </button>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4"><SeverityBadge severity={f.severity} /></td>
                        <td className="px-6 py-4 text-sm">
                          <select value={f.status || 'Investigating'} onChange={(e) => updateStatus(f.id, e.target.value)} onClick={(e) => e.stopPropagation()} className="bg-black/40 border border-white/10 rounded-lg px-2 py-1 text-slate-300 focus:outline-none focus:border-red-500/50">
                            <option value="Investigating">Investigating</option>
                            <option value="Confirmed">Confirmed</option>
                            <option value="Reported">Reported</option>
                            <option value="Duplicate">Duplicate</option>
                            <option value="False Positive">False Positive</option>
                            <option value="N/A">N/A</option>
                          </select>
                        </td>
                      </tr>
                    )})}
                  </tbody>
                </table>
              )}
            </div>

            {findings.length > 0 && (
              <div className="flex items-center justify-between text-sm text-slate-400 px-2">
                <div>Page {currentPage} of {totalPages} <span className="ml-2 text-slate-500">({searchedFindings.length} results)</span></div>
                <div className="flex gap-2">
                  <button type="button" onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1} className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 disabled:opacity-30 transition">
                    <ChevronLeft className="w-4 h-4" /> Prev
                  </button>
                  <button type="button" onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages} className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 disabled:opacity-30 transition">
                    Next <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'analysis' && (
          <div className="mb-6 rounded-3xl border border-white/10 bg-white/5 p-6 shadow-2xl backdrop-blur-xl overflow-hidden">
            <div className="mb-4 flex items-center gap-3">
              <Sparkles className="h-5 w-5 text-purple-400" />
              <h2 className="text-lg font-semibold text-white">Executive AI Assessment</h2>
            </div>
            <div className="text-slate-300 text-sm break-words">
              {aiAnalysis ? (
                <ReactMarkdown
                  components={{
                    h1: ({node, ...props}) => <h1 className="text-2xl font-bold text-white mt-6 mb-4" {...props} />,
                    h2: ({node, ...props}) => <h2 className="text-xl font-semibold text-red-400 mt-5 mb-3 border-b border-white/10 pb-2" {...props} />,
                    h3: ({node, ...props}) => <h3 className="text-lg font-medium text-white mt-4 mb-2" {...props} />,
                    p: ({node, ...props}) => <p className="text-sm text-slate-300 leading-relaxed mb-4" {...props} />,
                    strong: ({node, ...props}) => <strong className="font-bold text-red-500" {...props} />,
                    ul: ({node, ...props}) => <ul className="list-disc list-inside space-y-1 mb-4 text-sm text-slate-300" {...props} />,
                    li: ({node, ...props}) => <li className="leading-relaxed" {...props} />,
                    code: ({node, ...props}) => <code className="bg-black/50 text-red-400 px-1.5 py-0.5 rounded text-xs font-mono border border-white/10" {...props} />
                  }}
                >
                  {aiAnalysis}
                </ReactMarkdown>
              ) : (
                'No analysis available.'
              )}
            </div>
          </div>
        )}
        </div>
      </div>
    </div>
  )
}
