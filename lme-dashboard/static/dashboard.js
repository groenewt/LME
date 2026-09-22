const nativeFetch = window.fetch.bind(window);
window.fetch = async (...args) => {
  const response = await nativeFetch(...args);
  if (response.status === 401) window.dispatchEvent(new CustomEvent('lme-identity-required'));
  return response;
};
function linkify(text) {
  // Escape HTML first to prevent XSS
  const div = document.createElement('div');
  div.textContent = text;
  let safe = div.innerHTML;
  // Convert URLs to clickable links
  safe = safe.replace(/(https?:\/\/[^\s<]+)/g,
    '<a href="$1" target="_blank" rel="noopener" class="text-purple-400 hover:text-purple-300 underline">$1</a>');
  return safe;
}
function dashboard() {
  return {
    __csp_000: function() { with (this) { return (identityRequired); } },
    __csp_001: function() { with (this) { window.location.reload() } },
    __csp_002: function() { with (this) { return (health.elasticsearch === 'green' ? 'bg-green-900 text-green-300' :
                           health.elasticsearch === 'yellow' ? 'bg-yellow-900 text-yellow-300' :
                           'bg-red-900 text-red-300'); } },
    __csp_003: function() { with (this) { return (health.elasticsearch === 'green' ? 'bg-green-400' :
                    health.elasticsearch === 'yellow' ? 'bg-yellow-400' : 'bg-red-400'); } },
    __csp_004: function() { with (this) { return (health.elasticsearch || '…'); } },
    __csp_005: function() { with (this) { return (health.litellm === 'ok' ? 'bg-green-900 text-green-300' : 'bg-red-900 text-red-300'); } },
    __csp_006: function() { with (this) { return (health.litellm === 'ok' ? 'bg-green-400' : 'bg-red-400'); } },
    __csp_007: function() { with (this) { return (health.litellm || '…'); } },
    __csp_008: function() { with (this) { return (health.pgvector === 'ok' ? 'bg-green-900 text-green-300' : 'bg-red-900 text-red-300'); } },
    __csp_009: function() { with (this) { return (health.pgvector === 'ok' ? 'bg-green-400' : 'bg-red-400'); } },
    __csp_010: function() { with (this) { return (health.pgvector || '…'); } },
    __csp_011: function() { with (this) { mainView = 'settings'; settingsSection = 'models'; loadModels(); loadLocalModels() } },
    __csp_012: function() { with (this) { return (activeModelIsLocal ? 'bg-purple-900 text-purple-300' : 'bg-sky-900 text-sky-300'); } },
    __csp_013: function() { with (this) { return (activeModelIsLocal); } },
    __csp_014: function() { with (this) { return (!activeModelIsLocal); } },
    __csp_015: function() { with (this) { return (modelSettings.activeModel || '…'); } },
    __csp_016: function() { with (this) { loadAll() } },
    __csp_017: function() { with (this) { mainView = 'alerts' } },
    __csp_018: function() { with (this) { return (mainView === 'alerts' ? 'bg-surface-700 text-white' : 'text-gray-500 hover:text-gray-300'); } },
    __csp_019: function() { with (this) { mainView = 'vulns'; if(!vulns._loaded) loadVulns() } },
    __csp_020: function() { with (this) { return (mainView === 'vulns' ? 'bg-surface-700 text-white' : 'text-gray-500 hover:text-gray-300'); } },
    __csp_021: function() { with (this) { return (vulns.totalVulns > 0); } },
    __csp_022: function() { with (this) { return (vulns.totalVulns); } },
    __csp_023: function() { with (this) { mainView = 'detection'; if (!kibanaRules._loaded) loadKibanaRules(); if (!sigma._loaded) loadSigmaStatus(); if (!prebuilt.status) loadPrebuiltStatus() } },
    __csp_024: function() { with (this) { return (mainView === 'detection' ? 'bg-surface-700 text-white' : 'text-gray-500 hover:text-gray-300'); } },
    __csp_025: function() { with (this) { mainView = 'telemetry'; loadTelemetry() } },
    __csp_026: function() { with (this) { return (mainView === 'telemetry' ? 'bg-surface-700 text-white' : 'text-gray-500 hover:text-gray-300'); } },
    __csp_027: function() { with (this) { mainView = 'settings'; loadModels(); loadLocalModels(); if (!kev.status) loadKevStatus() } },
    __csp_028: function() { with (this) { return (mainView === 'settings' ? 'bg-surface-700 text-white' : 'text-gray-500 hover:text-gray-300'); } },
    __csp_029: function() { with (this) { return (mainView === 'alerts'); } },
    __csp_030: function() { with (this) { activeTab = 'kibana' } },
    __csp_031: function() { with (this) { return (activeTab === 'kibana' ? 'border-blue-400 text-white' : 'border-transparent text-gray-500 hover:text-gray-300'); } },
    __csp_032: function() { with (this) { return (kibana.total > 0); } },
    __csp_033: function() { with (this) { return (kibana.total); } },
    __csp_034: function() { with (this) { activeTab = 'wazuh' } },
    __csp_035: function() { with (this) { return (activeTab === 'wazuh' ? 'border-orange-400 text-white' : 'border-transparent text-gray-500 hover:text-gray-300'); } },
    __csp_036: function() { with (this) { return (wazuh.total > 0); } },
    __csp_037: function() { with (this) { return (wazuh.total); } },
    __csp_038: function() { with (this) { activeTab = 'sysmon' } },
    __csp_039: function() { with (this) { return (activeTab === 'sysmon' ? 'border-red-400 text-white' : 'border-transparent text-gray-500 hover:text-gray-300'); } },
    __csp_040: function() { with (this) { return (sysmon.total > 0); } },
    __csp_041: function() { with (this) { return (sysmon.total); } },
    __csp_042: function() { with (this) { activeTab = 'defender' } },
    __csp_043: function() { with (this) { return (activeTab === 'defender' ? 'border-green-400 text-white' : 'border-transparent text-gray-500 hover:text-gray-300'); } },
    __csp_044: function() { with (this) { return (defender.total > 0); } },
    __csp_045: function() { with (this) { return (defender.total); } },
    __csp_046: function() { with (this) { loadKibana(); loadWazuh(); loadSysmon(); loadDefender() } },
    __csp_047: function() { with (this) { searchQuery = ''; loadKibana(); loadWazuh(); loadSysmon(); loadDefender() } },
    __csp_048: function() { with (this) { return (searchQuery); } },
    __csp_049: function() { with (this) { return (hosts.length > 1); } },
    __csp_050: function(h) { with (this) { return (h); } },
    __csp_051: function() { with (this) { return (activeTab === 'kibana'); } },
    __csp_052: function() { with (this) { loadKibana() } },
    __csp_053: function() { with (this) { return (activeTab === 'wazuh'); } },
    __csp_054: function() { with (this) { loadWazuh() } },
    __csp_055: function() { with (this) { return (activeTab === 'sysmon'); } },
    __csp_056: function() { with (this) { return (activeTab === 'defender'); } },
    __csp_057: function() { with (this) { loadDefender() } },
    __csp_058: function() { with (this) { 
           const el = $refs.alertScroll;
           if (el.scrollTop + el.clientHeight >= el.scrollHeight - 200) {
             if (activeTab === 'kibana') loadMoreKibana();
             else if (activeTab === 'wazuh') loadMoreWazuh();
             else if (activeTab === 'sysmon') loadMoreSysmon();
             else if (activeTab === 'defender') loadMoreDefender();
           }
          } },
    __csp_059: function() { with (this) { return ((activeTab === 'kibana' && kibana.loading) || (activeTab === 'wazuh' && wazuh.loading) || (activeTab === 'sysmon' && sysmon.loading) || (activeTab === 'defender' && defender.loading)); } },
    __csp_060: function() { with (this) { return (activeTab === 'kibana' && kibana.error); } },
    __csp_061: function() { with (this) { return (kibana.error); } },
    __csp_062: function() { with (this) { return (activeTab === 'sysmon' && sysmon.error); } },
    __csp_063: function() { with (this) { return (sysmon.error); } },
    __csp_064: function() { with (this) { return (activeTab === 'defender' && defender.error); } },
    __csp_065: function() { with (this) { return (defender.error); } },
    __csp_066: function() { with (this) { return (activeTab === 'wazuh' && wazuh.error); } },
    __csp_067: function() { with (this) { return (wazuh.error); } },
    __csp_068: function() { with (this) { return (activeTab === 'kibana' && !kibana.loading && !kibana.error && kibana.alerts.length === 0); } },
    __csp_069: function() { with (this) { return (activeTab === 'wazuh' && !wazuh.loading && !wazuh.error && wazuh.alerts.length === 0); } },
    __csp_070: function() { with (this) { return (activeTab === 'defender' && !defender.loading && !defender.error && defender.alerts.length === 0); } },
    __csp_071: function() { with (this) { return (activeTab === 'sysmon' && !sysmon.loading && !sysmon.error && sysmon.alerts.length === 0); } },
    __csp_072: function() { with (this) { return (activeTab === 'kibana' && !kibana.loading); } },
    __csp_073: function(alert) { with (this) { return (alert.id); } },
    __csp_074: function(alert) { with (this) { return (severityBorder(alert.severity)); } },
    __csp_075: function(alert) { with (this) { return (severityBadge(alert.severity)); } },
    __csp_076: function(alert) { with (this) { return (alert.severity); } },
    __csp_077: function(alert) { with (this) { return (alert.rule_name); } },
    __csp_078: function(alert) { with (this) { return (fmtTime(alert.timestamp)); } },
    __csp_079: function(alert) { with (this) { return (alert.host); } },
    __csp_080: function(alert) { with (this) { return (alert.user); } },
    __csp_081: function(alert) { with (this) { return (alert.src_ip); } },
    __csp_082: function(alert) { with (this) { return (alert.reason); } },
    __csp_083: function(alert) { with (this) { analyzeAlert(alert, 'kibana') } },
    __csp_084: function(alert) { with (this) { alert._expanded = !alert._expanded } },
    __csp_085: function(alert) { with (this) { return (alert._expanded ? 'Hide' : 'Details'); } },
    __csp_086: function(alert) { with (this) { return (alert._expanded); } },
    __csp_087: function(alert) { with (this) { return (alert.command); } },
    __csp_088: function(alert) { with (this) { return (alert.dst_ip); } },
    __csp_089: function(alert) { with (this) { return (JSON.stringify(alert._raw, null, 2)); } },
    __csp_090: function(alert) { with (this) { return (alert._analysis); } },
    __csp_091: function(alert) { with (this) { return (alert._analyzing); } },
    __csp_092: function() { with (this) { return (activeTab === 'wazuh' && !wazuh.loading); } },
    __csp_093: function(alert) { with (this) { return ('L' + alert.level); } },
    __csp_094: function(alert) { with (this) { return (alert.agent_name); } },
    __csp_095: function(alert) { with (this) { return (alert.rule_id); } },
    __csp_096: function(alert) { with (this) { return (alert.groups && alert.groups.length); } },
    __csp_097: function(g) { with (this) { return (g); } },
    __csp_098: function(alert) { with (this) { analyzeAlert(alert, 'wazuh') } },
    __csp_099: function(alert) { with (this) { return (alert.full_log); } },
    __csp_100: function(alert) { with (this) { return (alert.location); } },
    __csp_101: function() { with (this) { return (activeTab === 'sysmon' && !sysmon.loading); } },
    __csp_102: function(alert) { with (this) { return ('ID ' + alert.event_id + ' ' + alert.event_name); } },
    __csp_103: function(alert) { with (this) { return (alert.summary); } },
    __csp_104: function(alert) { with (this) { return (alert.image); } },
    __csp_105: function(alert) { with (this) { return (alert.target); } },
    __csp_106: function(alert) { with (this) { analyzeAlert(alert, 'sysmon') } },
    __csp_107: function(alert) { with (this) { return (alert.command_line); } },
    __csp_108: function() { with (this) { return (activeTab === 'defender' && !defender.loading); } },
    __csp_109: function(alert) { with (this) { return (alert.event_id); } },
    __csp_110: function(alert) { with (this) { return ('ID ' + alert.event_id); } },
    __csp_111: function(alert) { with (this) { return (alert.threat_name); } },
    __csp_112: function(alert) { with (this) { return (alert.category); } },
    __csp_113: function(alert) { with (this) { return (alert.action); } },
    __csp_114: function(alert) { with (this) { return (alert.path); } },
    __csp_115: function(alert) { with (this) { analyzeAlert(alert, 'defender') } },
    __csp_116: function(alert) { with (this) { return (alert.source); } },
    __csp_117: function(alert) { with (this) { return (alert.severity_name); } },
    __csp_118: function() { with (this) { return ((activeTab === 'kibana' && kibana.loadingMore) || (activeTab === 'wazuh' && wazuh.loadingMore) || (activeTab === 'sysmon' && sysmon.loadingMore) || (activeTab === 'defender' && defender.loadingMore)); } },
    __csp_119: function() { with (this) { return (activeTab === 'kibana' && !kibana.loading && !kibana.loadingMore && kibana.alerts.length > 0 && !kibana.nextCursor); } },
    __csp_120: function() { with (this) { return (activeTab === 'wazuh' && !wazuh.loading && !wazuh.loadingMore && wazuh.alerts.length > 0 && !wazuh.nextCursor); } },
    __csp_121: function() { with (this) { return (activeTab === 'sysmon' && !sysmon.loading && !sysmon.loadingMore && sysmon.alerts.length > 0 && !sysmon.nextCursor); } },
    __csp_122: function() { with (this) { return (activeTab === 'defender' && !defender.loading && !defender.loadingMore && defender.alerts.length > 0 && !defender.nextCursor); } },
    __csp_123: function() { with (this) { return (mainView === 'detection'); } },
    __csp_124: function() { with (this) { detTab = 'rules' } },
    __csp_125: function() { with (this) { return (detTab === 'rules' ? 'bg-surface-700 text-white' : 'text-gray-500 hover:text-gray-300'); } },
    __csp_126: function() { with (this) { detTab = 'elastalert'; if (!eaRules._loaded) loadEaRules() } },
    __csp_127: function() { with (this) { return (detTab === 'elastalert' ? 'bg-surface-700 text-white' : 'text-gray-500 hover:text-gray-300'); } },
    __csp_128: function() { with (this) { return ('(' + eaRules.rules.length + ')'); } },
    __csp_129: function() { with (this) { detTab = 'kev'; if (!kev.status) loadKevStatus(); if (!kevMatched._loaded) loadKevMatched() } },
    __csp_130: function() { with (this) { return (detTab === 'kev' ? 'bg-surface-700 text-white' : 'text-gray-500 hover:text-gray-300'); } },
    __csp_131: function() { with (this) { return (kev.status && kev.status.matched_cves > 0); } },
    __csp_132: function() { with (this) { return (kev.status.matched_cves); } },
    __csp_133: function() { with (this) { return (detTab === 'rules'); } },
    __csp_134: function() { with (this) { return (prebuilt.status); } },
    __csp_135: function() { with (this) { return (prebuilt.status.rules_installed + ' installed'); } },
    __csp_136: function() { with (this) { return (prebuilt.status.rules_not_installed > 0); } },
    __csp_137: function() { with (this) { return (' · ' + prebuilt.status.rules_not_installed + ' available'); } },
    __csp_138: function() { with (this) { return (prebuilt.status.rules_not_updated > 0); } },
    __csp_139: function() { with (this) { return (' · ' + prebuilt.status.rules_not_updated + ' updates'); } },
    __csp_140: function() { with (this) { return (prebuilt.status.rules_not_installed === 0 && prebuilt.status.rules_not_updated === 0); } },
    __csp_141: function() { with (this) { installPrebuiltRules() } },
    __csp_142: function() { with (this) { return (prebuilt.installing || (prebuilt.status && prebuilt.status.rules_not_installed === 0 && prebuilt.status.rules_not_updated === 0)); } },
    __csp_143: function() { with (this) { return (prebuilt.installing); } },
    __csp_144: function() { with (this) { return (prebuilt.installing ? 'Importing…' : 'Import Prebuilt'); } },
    __csp_145: function() { with (this) { return (prebuilt.message); } },
    __csp_146: function() { with (this) { return (prebuilt.error ? 'text-red-400' : 'text-green-400'); } },
    __csp_147: function() { with (this) { sigmaConvert() } },
    __csp_148: function() { with (this) { return (sigma.converting); } },
    __csp_149: function() { with (this) { return (!sigma.converting); } },
    __csp_150: function() { with (this) { return (sigma.converting ? 'Downloading…' : 'Download & Convert'); } },
    __csp_151: function() { with (this) { return (sigma.fileUploading ? 'opacity-60 pointer-events-none' : ''); } },
    __csp_152: function() { with (this) { return (sigma.fileUploading ? 'animate-spin' : ''); } },
    __csp_153: function() { with (this) { return (sigma.fileUploading ? 'Uploading…' : 'Upload NDJSON'); } },
    __csp_154: function($event) { with (this) { sigmaUploadFile($event) } },
    __csp_155: function() { with (this) { return (sigma.yamlUploading ? 'opacity-60 pointer-events-none' : ''); } },
    __csp_156: function() { with (this) { return (sigma.yamlUploading ? 'animate-spin' : ''); } },
    __csp_157: function() { with (this) { return (sigma.yamlUploading ? 'Converting…' : 'Upload YAML'); } },
    __csp_158: function($event) { with (this) { sigmaUploadYaml($event) } },
    __csp_159: function() { with (this) { return (sigma.message); } },
    __csp_160: function() { with (this) { return (sigma.error ? 'bg-red-900/30 border border-red-700 text-red-300' : 'bg-green-900/30 border border-green-700 text-green-300'); } },
    __csp_161: function() { with (this) { return (sigma.fileMessage); } },
    __csp_162: function() { with (this) { return (sigma.fileError ? 'bg-red-900/30 border border-red-700 text-red-300' : 'bg-green-900/30 border border-green-700 text-green-300'); } },
    __csp_163: function() { with (this) { return (sigma.totalRules > 0); } },
    __csp_164: function(platform) { with (this) { return (platform); } },
    __csp_165: function(info) { with (this) { return (info.rule_count + ' rules'); } },
    __csp_166: function(info) { with (this) { return (info.modified); } },
    __csp_167: function(info) { with (this) { return ('Converted: ' + (info.modified ? new Date(info.modified).toLocaleString() : '')); } },
    __csp_168: function(platform) { with (this) { sigmaUpload(platform) } },
    __csp_169: function(platform) { with (this) { return (sigma.uploading === platform); } },
    __csp_170: function(platform) { with (this) { return (sigma.uploading === platform ? 'Uploading…' : 'Upload to Kibana'); } },
    __csp_171: function() { with (this) { return (!sigma.converting && sigma.totalRules === 0 && !sigma.message); } },
    __csp_172: function() { with (this) { return ('(' + kibanaRules.total + ' rules)'); } },
    __csp_173: function() { with (this) { kibanaRules.page=1; loadKibanaRules() } },
    __csp_174: function() { with (this) { loadKibanaRules() } },
    __csp_175: function(tag) { with (this) { return (tag); } },
    __csp_176: function(tag) { with (this) { return (tag.replace('OS: ', '')); } },
    __csp_177: function(tag) { with (this) { bulkActionByTag('enable', tag) } },
    __csp_178: function(tag) { with (this) { bulkActionByTag('disable', tag) } },
    __csp_179: function() { with (this) { return (kibanaRules.selected.size > 0); } },
    __csp_180: function() { with (this) { return (kibanaRules.selected.size + ' selected'); } },
    __csp_181: function() { with (this) { bulkToggleKibanaRules(true) } },
    __csp_182: function() { with (this) { bulkToggleKibanaRules(false) } },
    __csp_183: function() { with (this) { kibanaRules.selected = new Set() } },
    __csp_184: function() { with (this) { return (kibanaRules.loading); } },
    __csp_185: function() { with (this) { return (!kibanaRules.loading && kibanaRules.rules.length > 0); } },
    __csp_186: function() { with (this) { return (kibanaRules.selected.size === kibanaRules.rules.length && kibanaRules.rules.length > 0); } },
    __csp_187: function() { with (this) { toggleSelectAll() } },
    __csp_188: function() { with (this) { sortKibanaRules('name') } },
    __csp_189: function() { with (this) { return (kibanaRules.sortField === 'name'); } },
    __csp_190: function() { with (this) { return (kibanaRules.sortOrder === 'asc' ? ' ▲' : ' ▼'); } },
    __csp_191: function() { with (this) { sortKibanaRules('severity') } },
    __csp_192: function() { with (this) { return (kibanaRules.sortField === 'severity'); } },
    __csp_193: function() { with (this) { sortKibanaRules('risk_score') } },
    __csp_194: function() { with (this) { return (kibanaRules.sortField === 'risk_score'); } },
    __csp_195: function() { with (this) { sortKibanaRules('enabled') } },
    __csp_196: function() { with (this) { return (kibanaRules.sortField === 'enabled'); } },
    __csp_197: function(rule) { with (this) { return (rule.id); } },
    __csp_198: function(rule) { with (this) { return (kibanaRules.selected.has(rule.id) ? 'bg-blue-900/10' : ''); } },
    __csp_199: function(rule) { with (this) { return (kibanaRules.selected.has(rule.id)); } },
    __csp_200: function(rule) { with (this) { toggleSelectRule(rule.id) } },
    __csp_201: function(rule) { with (this) { toggleKibanaRule(rule) } },
    __csp_202: function(rule) { with (this) { return (rule.enabled ? 'bg-blue-600' : 'bg-surface-600'); } },
    __csp_203: function(rule) { with (this) { return (rule.enabled ? 'translate-x-4' : ''); } },
    __csp_204: function(rule) { with (this) { return (rule.name); } },
    __csp_205: function(rule) { with (this) { return (rule.description); } },
    __csp_206: function(rule) { with (this) { return (severityBadge(rule.severity)); } },
    __csp_207: function(rule) { with (this) { return (rule.severity); } },
    __csp_208: function(rule) { with (this) { return (rule.risk_score); } },
    __csp_209: function(rule) { with (this) { return (rule.enabled ? 'text-green-400' : 'text-gray-600'); } },
    __csp_210: function(rule) { with (this) { return (rule.enabled ? 'Active' : 'Disabled'); } },
    __csp_211: function() { with (this) { return ('Showing ' + ((kibanaRules.page-1)*kibanaRules.perPage+1) + '-' + Math.min(kibanaRules.page*kibanaRules.perPage, kibanaRules.total) + ' of ' + kibanaRules.total); } },
    __csp_212: function() { with (this) { kibanaRules.page--; loadKibanaRules() } },
    __csp_213: function() { with (this) { return (kibanaRules.page <= 1); } },
    __csp_214: function() { with (this) { kibanaRules.page++; loadKibanaRules() } },
    __csp_215: function() { with (this) { return (kibanaRules.page * kibanaRules.perPage >= kibanaRules.total); } },
    __csp_216: function() { with (this) { return (!kibanaRules.loading && kibanaRules.rules.length === 0); } },
    __csp_217: function() { with (this) { return (detTab === 'elastalert'); } },
    __csp_218: function() { with (this) { loadEaRules() } },
    __csp_219: function() { with (this) { return (eaRules.loading); } },
    __csp_220: function() { with (this) { return (eaRules.loading ? 'animate-spin' : ''); } },
    __csp_221: function() { with (this) { eaRules.showPasteModal = true; eaRules.pasteMessage = null } },
    __csp_222: function() { with (this) { return (eaRules.uploading ? 'opacity-60 pointer-events-none' : ''); } },
    __csp_223: function() { with (this) { return (eaRules.uploading ? 'animate-spin' : ''); } },
    __csp_224: function() { with (this) { return (eaRules.uploading ? 'Uploading…' : 'Upload File'); } },
    __csp_225: function($event) { with (this) { uploadEaRules($event) } },
    __csp_226: function() { with (this) { return (eaRules.uploadMessage); } },
    __csp_227: function() { with (this) { return (eaRules.uploadError ? 'bg-red-900/30 border border-red-700 text-red-300' : 'bg-green-900/30 border border-green-700 text-green-300'); } },
    __csp_228: function() { with (this) { return (eaRules.error); } },
    __csp_229: function() { with (this) { return (eaRules.loading && !eaRules.rules.length); } },
    __csp_230: function() { with (this) { return (!eaRules.loading && eaRules.rules.length === 0); } },
    __csp_231: function(rule) { with (this) { return (rule.filename); } },
    __csp_232: function() { with (this) { return (idx > 0 ? 'border-t border-surface-600' : ''); } },
    __csp_233: function(rule) { with (this) { toggleEaRule(rule.filename) } },
    __csp_234: function(rule) { with (this) { return (eaRules.expanded === rule.filename ? 'rotate-90' : ''); } },
    __csp_235: function(rule) { with (this) { return (rule.type !== 'unknown'); } },
    __csp_236: function(rule) { with (this) { return (rule.type); } },
    __csp_237: function(rule) { with (this) { return (rule.index); } },
    __csp_238: function(rule) { with (this) { deleteEaRule(rule.filename) } },
    __csp_239: function(rule) { with (this) { return (eaRules.deleting === rule.filename); } },
    __csp_240: function(rule) { with (this) { return (eaRules.expanded === rule.filename); } },
    __csp_241: function(rule) { with (this) { return (eaRules.loadingYaml === rule.filename); } },
    __csp_242: function(rule) { with (this) { return (eaRules.loadingYaml !== rule.filename && eaRules.yamlCache[rule.filename] !== undefined); } },
    __csp_243: function(rule) { with (this) { return (eaRules.yamlCache[rule.filename]); } },
    __csp_244: function() { with (this) { return (detTab === 'kev'); } },
    __csp_245: function() { with (this) { return (kev.status ? kev.status.total_kev : '—'); } },
    __csp_246: function() { with (this) { return (kev.status && kev.status.matched_cves > 0 ? 'text-orange-400' : 'text-white'); } },
    __csp_247: function() { with (this) { return (kev.status ? kev.status.matched_cves : '—'); } },
    __csp_248: function() { with (this) { return (kev.status && kev.status.overdue_count > 0 ? 'text-red-400' : 'text-white'); } },
    __csp_249: function() { with (this) { return (kev.status ? kev.status.overdue_count : '—'); } },
    __csp_250: function() { with (this) { return (kev.status && kev.status.last_pull_timestamp ? fmtTime(kev.status.last_pull_timestamp) : 'Never'); } },
    __csp_251: function() { with (this) { kevPull() } },
    __csp_252: function() { with (this) { return (kev.pulling); } },
    __csp_253: function() { with (this) { return (kev.pulling ? 'Syncing…' : 'Sync Now'); } },
    __csp_254: function() { with (this) { return (kev.pullMessage); } },
    __csp_255: function() { with (this) { return (kev.pullError ? 'bg-red-900/30 border border-red-700 text-red-300' : 'bg-green-900/30 border border-green-700 text-green-300'); } },
    __csp_256: function() { with (this) { loadKevMatched() } },
    __csp_257: function() { with (this) { return (kevMatched.loading ? 'animate-spin' : ''); } },
    __csp_258: function() { with (this) { return (kevMatched.loading); } },
    __csp_259: function() { with (this) { return (!kevMatched.loading && kevMatched.items.length === 0); } },
    __csp_260: function() { with (this) { return (!kevMatched.loading && kevMatched.items.length > 0); } },
    __csp_261: function(item) { with (this) { return (item.cve_id); } },
    __csp_262: function(item) { with (this) { return (item.overdue ? 'border-red-700' : 'border-surface-600'); } },
    __csp_263: function(item) { with (this) { return ('https://nvd.nist.gov/vuln/detail/' + item.cve_id); } },
    __csp_264: function(item) { with (this) { return (item.overdue); } },
    __csp_265: function(item) { with (this) { return (item.ransomware === 'Known'); } },
    __csp_266: function(item) { with (this) { return (severityBadge(item.severity)); } },
    __csp_267: function(item) { with (this) { return (item.severity || 'N/A'); } },
    __csp_268: function(item) { with (this) { return (item.cvss); } },
    __csp_269: function(item) { with (this) { return ('CVSS ' + (item.cvss ? item.cvss.toFixed(1) : '')); } },
    __csp_270: function(item) { with (this) { return (item.name); } },
    __csp_271: function(item) { with (this) { return (item.vendor + ' — ' + item.product); } },
    __csp_272: function(item) { with (this) { return (item.overdue ? 'text-red-400' : 'text-yellow-400'); } },
    __csp_273: function(item) { with (this) { return (item.due_date || 'N/A'); } },
    __csp_274: function(item) { with (this) { return ('Added ' + item.date_added); } },
    __csp_275: function(item) { with (this) { return (item.description); } },
    __csp_276: function() { with (this) { return (host); } },
    __csp_277: function(item) { with (this) { return (item.host_count === 0); } },
    __csp_278: function(item) { with (this) { return (item.host_count + ' host(s)'); } },
    __csp_279: function(item) { with (this) { return (item.required_action); } },
    __csp_280: function() { with (this) { return (eaRules.showPasteModal); } },
    __csp_281: function() { with (this) { eaRules.showPasteModal = false } },
    __csp_282: function() { with (this) { return (eaRules.pasteMessage); } },
    __csp_283: function() { with (this) { return (eaRules.pasteError ? 'text-red-400' : 'text-green-400'); } },
    __csp_284: function() { with (this) { return (!eaRules.pasteMessage); } },
    __csp_285: function() { with (this) { pasteEaRule() } },
    __csp_286: function() { with (this) { return (eaRules.pasting || !eaRules.pasteYaml.trim()); } },
    __csp_287: function() { with (this) { return (eaRules.pasting ? 'animate-spin' : ''); } },
    __csp_288: function() { with (this) { return (eaRules.pasting ? 'Saving…' : 'Save Rule'); } },
    __csp_289: function() { with (this) { return (mainView === 'vulns'); } },
    __csp_290: function() { with (this) { return (vulns.agents.length); } },
    __csp_291: function() { with (this) { loadVulns() } },
    __csp_292: function() { with (this) { return (vulns.loading ? 'animate-spin' : ''); } },
    __csp_293: function() { with (this) { return (vulns.loading); } },
    __csp_294: function() { with (this) { return (vulns.error); } },
    __csp_295: function() { with (this) { return (!vulns.loading && !vulns.error && vulns.agents.length === 0); } },
    __csp_296: function() { with (this) { return (!vulns.loading && vulns.agents.length > 0); } },
    __csp_297: function() { with (this) { return (agent.agent_id); } },
    __csp_298: function() { with (this) { toggleAgentDetail(agent) } },
    __csp_299: function() { with (this) { return (idx === 0 ? 'bg-red-900 text-red-300' : idx < 3 ? 'bg-orange-900 text-orange-300' : 'bg-surface-700 text-gray-400'); } },
    __csp_300: function() { with (this) { return (idx + 1); } },
    __csp_301: function() { with (this) { return (agent.agent_name); } },
    __csp_302: function() { with (this) { return ('ID: ' + agent.agent_id); } },
    __csp_303: function() { with (this) { return (agent.os); } },
    __csp_304: function() { with (this) { return (agent.critical > 0); } },
    __csp_305: function() { with (this) { return (agent.critical + ' Critical'); } },
    __csp_306: function() { with (this) { return (agent.high > 0); } },
    __csp_307: function() { with (this) { return (agent.high + ' High'); } },
    __csp_308: function() { with (this) { return (agent.medium > 0); } },
    __csp_309: function() { with (this) { return (agent.medium + ' Med'); } },
    __csp_310: function() { with (this) { return (agent.low > 0); } },
    __csp_311: function() { with (this) { return (agent.low + ' Low'); } },
    __csp_312: function() { with (this) { return (agent.total + ' CVEs'); } },
    __csp_313: function() { with (this) { return (agent.max_cvss >= 9 ? 'text-red-400' : agent.max_cvss >= 7 ? 'text-orange-400' : agent.max_cvss >= 4 ? 'text-yellow-400' : 'text-green-400'); } },
    __csp_314: function() { with (this) { return (agent.max_cvss.toFixed(1)); } },
    __csp_315: function() { with (this) { return ('width:' + (agent.total ? (agent.critical/agent.total*100) : 0) + '%'); } },
    __csp_316: function() { with (this) { return ('width:' + (agent.total ? (agent.high/agent.total*100) : 0) + '%'); } },
    __csp_317: function() { with (this) { return ('width:' + (agent.total ? (agent.medium/agent.total*100) : 0) + '%'); } },
    __csp_318: function() { with (this) { return ('width:' + (agent.total ? (agent.low/agent.total*100) : 0) + '%'); } },
    __csp_319: function() { with (this) { return (agent._expanded ? 'rotate-180' : ''); } },
    __csp_320: function() { with (this) { return (agent._expanded); } },
    __csp_321: function() { with (this) { loadAgentVulns(agent.agent_id, '', false) } },
    __csp_322: function() { with (this) { return (vulnDetail.sevFilter === '' ? 'bg-surface-600 text-white' : 'text-gray-400 hover:text-gray-200'); } },
    __csp_323: function() { with (this) { loadAgentVulns(agent.agent_id, 'Critical', false) } },
    __csp_324: function() { with (this) { return (vulnDetail.sevFilter === 'Critical' ? 'bg-red-900 text-red-300' : 'text-gray-400 hover:text-gray-200'); } },
    __csp_325: function() { with (this) { loadAgentVulns(agent.agent_id, 'High', false) } },
    __csp_326: function() { with (this) { return (vulnDetail.sevFilter === 'High' ? 'bg-orange-900 text-orange-300' : 'text-gray-400 hover:text-gray-200'); } },
    __csp_327: function() { with (this) { loadAgentVulns(agent.agent_id, 'Medium', false) } },
    __csp_328: function() { with (this) { return (vulnDetail.sevFilter === 'Medium' ? 'bg-yellow-900 text-yellow-300' : 'text-gray-400 hover:text-gray-200'); } },
    __csp_329: function() { with (this) { loadAgentVulns(agent.agent_id, 'Low', false) } },
    __csp_330: function() { with (this) { return (vulnDetail.sevFilter === 'Low' ? 'bg-green-900 text-green-300' : 'text-gray-400 hover:text-gray-200'); } },
    __csp_331: function() { with (this) { return (vulnDetail.loading); } },
    __csp_332: function($event) { with (this) { onVulnScroll($event) } },
    __csp_333: function() { with (this) { return (vi); } },
    __csp_334: function() { with (this) { return ('https://nvd.nist.gov/vuln/detail/' + vuln.cve_id); } },
    __csp_335: function() { with (this) { return (vuln.cve_id); } },
    __csp_336: function() { with (this) { return (vuln.is_kev); } },
    __csp_337: function() { with (this) { return (vuln.is_kev && vuln.kev_due_date); } },
    __csp_338: function() { with (this) { return (vuln.kev_due_date); } },
    __csp_339: function() { with (this) { return (vuln.kev_ransomware === 'Known'); } },
    __csp_340: function() { with (this) { return (severityBadge(vuln.severity.toLowerCase())); } },
    __csp_341: function() { with (this) { return (vuln.severity || 'N/A'); } },
    __csp_342: function() { with (this) { return ((vuln.cvss||0) >= 9 ? 'text-red-400' : (vuln.cvss||0) >= 7 ? 'text-orange-400' : (vuln.cvss||0) >= 4 ? 'text-yellow-400' : 'text-green-400'); } },
    __csp_343: function() { with (this) { return (vuln.cvss != null ? vuln.cvss.toFixed(1) : '—'); } },
    __csp_344: function() { with (this) { return (vuln.package); } },
    __csp_345: function() { with (this) { return (vuln.package_version); } },
    __csp_346: function() { with (this) { return (vuln.description); } },
    __csp_347: function() { with (this) { return (fmtTime(vuln.detected_at)); } },
    __csp_348: function() { with (this) { return (agent._expanded && !vulnDetail.loading && vulnDetail.vulns.length === 0); } },
    __csp_349: function() { with (this) { return ('Showing ' + vulnDetail.vulns.length + ' of ' + vulnDetail.total); } },
    __csp_350: function() { with (this) { return (vulnDetail.loading && vulnDetail.vulns.length > 0); } },
    __csp_351: function() { with (this) { return (!vulnDetail.hasMore && vulnDetail.vulns.length > 0 && !vulnDetail.loading); } },
    __csp_352: function() { with (this) { return (mainView === 'settings'); } },
    __csp_353: function() { with (this) { settingsSection = 'models' } },
    __csp_354: function() { with (this) { return (settingsSection === 'models' ? 'bg-surface-700 text-white' : 'text-gray-500 hover:text-gray-300 hover:bg-surface-700/50'); } },
    __csp_355: function() { with (this) { settingsSection = 'local-models' } },
    __csp_356: function() { with (this) { return (settingsSection === 'local-models' ? 'bg-surface-700 text-white' : 'text-gray-500 hover:text-gray-300 hover:bg-surface-700/50'); } },
    __csp_357: function() { with (this) { settingsSection = 'kev' } },
    __csp_358: function() { with (this) { return (settingsSection === 'kev' ? 'bg-surface-700 text-white' : 'text-gray-500 hover:text-gray-300 hover:bg-surface-700/50'); } },
    __csp_359: function() { with (this) { settingsSection = 'documents'; loadDocsStatus() } },
    __csp_360: function() { with (this) { return (settingsSection === 'documents' ? 'bg-surface-700 text-white' : 'text-gray-500 hover:text-gray-300 hover:bg-surface-700/50'); } },
    __csp_361: function() { with (this) { settingsSection = 'general' } },
    __csp_362: function() { with (this) { return (settingsSection === 'general' ? 'bg-surface-700 text-white' : 'text-gray-500 hover:text-gray-300 hover:bg-surface-700/50'); } },
    __csp_363: function() { with (this) { return (settingsSection === 'models'); } },
    __csp_364: function() { with (this) { return (modelSettings.activeModel || 'Loading...'); } },
    __csp_365: function() { with (this) { return (modelSettings.models.length === 0); } },
    __csp_366: function(i) { with (this) { return (i); } },
    __csp_367: function(m) { with (this) { return (m.model_name); } },
    __csp_368: function(m) { with (this) { return (m.provider === 'local' || m.provider === ''); } },
    __csp_369: function(m) { with (this) { return (m.provider && m.provider !== 'local'); } },
    __csp_370: function(m) { with (this) { return (m.model_name === modelSettings.activeModel); } },
    __csp_371: function(m) { with (this) { return (m.litellm_model); } },
    __csp_372: function(m) { with (this) { return (m.api_base); } },
    __csp_373: function(m) { with (this) { return (m.has_api_key); } },
    __csp_374: function(m) { with (this) { return (!m.has_api_key); } },
    __csp_375: function(m) { with (this) { return (m.model_name !== modelSettings.activeModel); } },
    __csp_376: function(m) { with (this) { setActiveModel(m.model_name) } },
    __csp_377: function(m) { with (this) { deleteModel(m.model_name) } },
    __csp_378: function() { with (this) { newModel.provider = 'local'; prefillModel() } },
    __csp_379: function() { with (this) { return (newModel.provider === 'local' ? 'border-purple-500 bg-purple-900/30 text-purple-200' : 'border-surface-600 text-gray-400 hover:border-gray-500'); } },
    __csp_380: function() { with (this) { newModel.provider = 'openai'; prefillModel() } },
    __csp_381: function() { with (this) { return (newModel.provider === 'openai' ? 'border-green-500 bg-green-900/30 text-green-200' : 'border-surface-600 text-gray-400 hover:border-gray-500'); } },
    __csp_382: function() { with (this) { newModel.provider = 'anthropic'; prefillModel() } },
    __csp_383: function() { with (this) { return (newModel.provider === 'anthropic' ? 'border-orange-500 bg-orange-900/30 text-orange-200' : 'border-surface-600 text-gray-400 hover:border-gray-500'); } },
    __csp_384: function() { with (this) { newModel.provider = 'openrouter'; prefillModel() } },
    __csp_385: function() { with (this) { return (newModel.provider === 'openrouter' ? 'border-blue-500 bg-blue-900/30 text-blue-200' : 'border-surface-600 text-gray-400 hover:border-gray-500'); } },
    __csp_386: function() { with (this) { return (modelSettings.providers[newModel.provider]?.models); } },
    __csp_387: function() { with (this) { return (s); } },
    __csp_388: function() { with (this) { newModel.litellm_model = s; if(!newModel.model_name) newModel.model_name = s.split('/').pop() } },
    __csp_389: function() { with (this) { return (modelSettings.providers[newModel.provider]?.needs_api_key); } },
    __csp_390: function() { with (this) { return (modelSettings.providers[newModel.provider]?.api_base || 'Leave empty for default'); } },
    __csp_391: function() { with (this) { addModel() } },
    __csp_392: function() { with (this) { return (!newModel.model_name || modelSettings.saving); } },
    __csp_393: function() { with (this) { return (!modelSettings.saving); } },
    __csp_394: function() { with (this) { return (modelSettings.saving); } },
    __csp_395: function() { with (this) { return (modelSettings.message); } },
    __csp_396: function() { with (this) { return (modelSettings.error ? 'text-red-400' : 'text-green-400'); } },
    __csp_397: function() { with (this) { return (settingsSection === 'local-models'); } },
    __csp_398: function() { with (this) { return (localModels.status.status === 'ready' ? 'bg-green-900/50 text-green-400' :
                       localModels.status.status === 'switching' ? 'bg-yellow-900/50 text-yellow-400' :
                       localModels.status.status === 'error' ? 'bg-red-900/50 text-red-400' :
                       'bg-gray-800 text-gray-500'); } },
    __csp_399: function() { with (this) { return (localModels.status.status === 'switching' ? 'Restarting...' :
                       localModels.status.status === 'error' ? 'Error' :
                       localModels.status.status === 'ready' ? 'Running' : 'Unknown'); } },
    __csp_400: function() { with (this) { return (localModels.status.status === 'error' && localModels.status.error); } },
    __csp_401: function() { with (this) { return (localModels.status.error); } },
    __csp_402: function() { with (this) { return (localModels.models.length === 0); } },
    __csp_403: function(m) { with (this) { return (m.filename); } },
    __csp_404: function(m) { with (this) { return (m.filename === localModels.activeModel ? 'border-green-700 bg-green-900/20' : 'border-surface-600 bg-surface-900 hover:border-surface-500'); } },
    __csp_405: function(m) { with (this) { return (m.filename === localModels.activeModel ? 'bg-green-900/50' : 'bg-surface-700'); } },
    __csp_406: function(m) { with (this) { return (m.filename === localModels.activeModel ? 'text-green-400' : 'text-gray-500'); } },
    __csp_407: function(m) { with (this) { return (m.filename === localModels.activeModel ? 'text-green-300' : 'text-gray-300'); } },
    __csp_408: function(m) { with (this) { return (m.size_mb + ' MB'); } },
    __csp_409: function(m) { with (this) { return (m.filename === localModels.activeModel); } },
    __csp_410: function(m) { with (this) { return (m.filename !== localModels.activeModel); } },
    __csp_411: function(m) { with (this) { switchLocalModel(m.filename) } },
    __csp_412: function() { with (this) { return (localModels.switching); } },
    __csp_413: function() { with (this) { return (!localModels.switching); } },
    __csp_414: function(m) { with (this) { deleteLocalModel(m.filename) } },
    __csp_415: function() { with (this) { return (localModels.downloads.length > 0); } },
    __csp_416: function(d) { with (this) { return (d.filename); } },
    __csp_417: function(d) { with (this) { return (d.downloaded_mb >= 1024 ? (d.downloaded_mb / 1024).toFixed(1) + ' GB' : d.downloaded_mb + ' MB'); } },
    __csp_418: function() { with (this) { searchModels() } },
    __csp_419: function() { with (this) { return (!localModels.searchQuery || localModels.searching); } },
    __csp_420: function() { with (this) { return (!localModels.searching); } },
    __csp_421: function() { with (this) { return (localModels.searching); } },
    __csp_422: function() { with (this) { return (localModels.searchResults.length > 0); } },
    __csp_423: function(repo) { with (this) { return (repo.repo_id); } },
    __csp_424: function(f) { with (this) { return (f.filename); } },
    __csp_425: function(f) { with (this) { return (f.size_mb); } },
    __csp_426: function(f) { with (this) { return (f.size_mb >= 1024 ? (f.size_mb / 1024).toFixed(1) + ' GB' : f.size_mb + ' MB'); } },
    __csp_427: function(f) { with (this) { return (f.quant); } },
    __csp_428: function(repo, f) { with (this) { downloadSearchResult(repo.repo_id, f.filename) } },
    __csp_429: function() { with (this) { return (localModels.downloading); } },
    __csp_430: function() { with (this) { return (localModels.searchDone && localModels.searchResults.length === 0); } },
    __csp_431: function() { with (this) { return (localModels.downloadMessage); } },
    __csp_432: function() { with (this) { return (localModels.downloadError ? 'text-red-400' : 'text-green-400'); } },
    __csp_433: function() { with (this) { return (localModels.message); } },
    __csp_434: function() { with (this) { return (localModels.messageError ? 'text-red-400' : 'text-green-400'); } },
    __csp_435: function() { with (this) { return (settingsSection === 'kev'); } },
    __csp_436: function() { with (this) { return (kev.loading); } },
    __csp_437: function() { with (this) { return (kev.error); } },
    __csp_438: function() { with (this) { return (kev.status && kev.status.last_pull_timestamp
                           ? kev.status.last_pull_timestamp : 'Never'); } },
    __csp_439: function() { with (this) { return (kev.status); } },
    __csp_440: function() { with (this) { return ({
                      'bg-green-900 text-green-300': kev.status.badge === 'current',
                      'bg-yellow-900 text-yellow-300': kev.status.badge === 'stale',
                      'bg-gray-700 text-gray-400':    kev.status.badge === 'never',
                    }); } },
    __csp_441: function() { with (this) { return (kev.status.badge === 'current' ? 'Current'
                           : kev.status.badge === 'stale'   ? 'Stale'
                           : 'Never pulled'); } },
    __csp_442: function() { with (this) { return (kev.pulling ? 'animate-spin' : ''); } },
    __csp_443: function() { with (this) { return (kev.pulling ? 'Pulling…' : 'Pull now'); } },
    __csp_444: function() { with (this) { return (kev.pullError
                 ? 'bg-red-900/30 border border-red-700 text-red-300'
                 : 'bg-green-900/30 border border-green-700 text-green-300'); } },
    __csp_445: function() { with (this) { kevSettings.auto_pull = !kevSettings.auto_pull; saveKevSettings() } },
    __csp_446: function() { with (this) { return (kevSettings.auto_pull ? 'bg-emerald-600' : 'bg-surface-600'); } },
    __csp_447: function() { with (this) { return (kevSettings.auto_pull ? 'translate-x-4' : 'translate-x-0'); } },
    __csp_448: function() { with (this) { return (kevSettings.auto_pull ? 'text-gray-300' : 'text-gray-600'); } },
    __csp_449: function() { with (this) { saveKevSettings() } },
    __csp_450: function() { with (this) { return (!kevSettings.auto_pull); } },
    __csp_451: function() { with (this) { kevSettings.alert_on_match = !kevSettings.alert_on_match } },
    __csp_452: function() { with (this) { return (kevSettings.alert_on_match ? 'bg-emerald-600' : 'bg-surface-600'); } },
    __csp_453: function() { with (this) { return (kevSettings.alert_on_match ? 'translate-x-4' : 'translate-x-0'); } },
    __csp_454: function() { with (this) { kevSettings.alert_on_overdue = !kevSettings.alert_on_overdue } },
    __csp_455: function() { with (this) { return (kevSettings.alert_on_overdue ? 'bg-emerald-600' : 'bg-surface-600'); } },
    __csp_456: function() { with (this) { return (kevSettings.alert_on_overdue ? 'translate-x-4' : 'translate-x-0'); } },
    __csp_457: function() { with (this) { kevSettings.ransomware_only = !kevSettings.ransomware_only } },
    __csp_458: function() { with (this) { return (kevSettings.ransomware_only ? 'bg-orange-600' : 'bg-surface-600'); } },
    __csp_459: function() { with (this) { return (kevSettings.ransomware_only ? 'translate-x-4' : 'translate-x-0'); } },
    __csp_460: function() { with (this) { return (kevSettings.message); } },
    __csp_461: function() { with (this) { return (kevSettings.error ? 'text-red-400' : 'text-green-400'); } },
    __csp_462: function() { with (this) { return (!kevSettings.message); } },
    __csp_463: function() { with (this) { return (kevSettings.saving); } },
    __csp_464: function() { with (this) { return (kevSettings.saving ? 'animate-spin' : ''); } },
    __csp_465: function() { with (this) { return (kevSettings.saving ? 'Saving…' : 'Save settings'); } },
    __csp_466: function() { with (this) { return (settingsSection === 'documents'); } },
    __csp_467: function() { with (this) { return (docsIndex.status); } },
    __csp_468: function() { with (this) { return (docsIndex.status.chunk_count > 0 ? 'text-green-400' : 'text-yellow-400'); } },
    __csp_469: function() { with (this) { return (docsIndex.status.chunk_count + ' chunks indexed'); } },
    __csp_470: function() { with (this) { return (docsIndex.status.last_ingested); } },
    __csp_471: function() { with (this) { return ('Last updated: ' + new Date(docsIndex.status.last_ingested).toLocaleString()); } },
    __csp_472: function() { with (this) { ingestDocs() } },
    __csp_473: function() { with (this) { return (docsIndex.ingesting); } },
    __csp_474: function() { with (this) { return (!docsIndex.ingesting); } },
    __csp_475: function() { with (this) { return (docsIndex.ingesting ? 'Scraping & indexing… this takes a few minutes' : 'Pull Latest Documentation'); } },
    __csp_476: function() { with (this) { return (docsIndex.message); } },
    __csp_477: function() { with (this) { return (docsIndex.error ? 'bg-red-900/30 border border-red-700 text-red-300' : 'bg-green-900/30 border border-green-700 text-green-300'); } },
    __csp_478: function() { with (this) { return (settingsSection === 'general'); } },
    __csp_479: function() { with (this) { toggleAutoRefresh() } },
    __csp_480: function() { with (this) { return (autoRefresh ? 'bg-blue-600' : 'bg-surface-600'); } },
    __csp_481: function() { with (this) { return (autoRefresh ? 'translate-x-4' : 'translate-x-0'); } },
    __csp_482: function() { with (this) { return (mainView === 'telemetry'); } },
    __csp_483: function() { with (this) { loadTelemetry() } },
    __csp_484: function(view) { with (this) { return (view); } },
    __csp_485: function(view) { with (this) { return (telemetryStateClass(telemetry[view].state)); } },
    __csp_486: function(view) { with (this) { return (telemetryStateLabel(telemetry[view].state)); } },
    __csp_487: function(view) { with (this) { return (telemetry[view].freshness); } },
    __csp_488: function(view) { with (this) { return ('Observed ' + fmtTime(telemetry[view].freshness?.observed_at)); } },
    __csp_489: function(view) { with (this) { return (telemetry[view].state === 'empty'); } },
    __csp_490: function(view) { with (this) { return (telemetry[view].state === 'filtered_empty'); } },
    __csp_491: function(view) { with (this) { return (telemetry[view].state === 'unavailable'); } },
    __csp_492: function(item) { with (this) { return (item.id || JSON.stringify(item)); } },
    __csp_493: function(item) { with (this) { return (item.message || item['event.dataset'] || item.index || 'Telemetry record'); } },
    __csp_494: function(item) { with (this) { return (fmtTime(item['@timestamp'])); } },
    __csp_495: function(source) { with (this) { return (source.source); } },
    __csp_496: function(source) { with (this) { return (telemetryStateClass(source.state)); } },
    __csp_497: function(source) { with (this) { return (source.reason || ''); } },
    __csp_498: function(source) { with (this) { return (telemetryStateLabel(source.state)); } },
    __csp_499: function() { with (this) { return (telemetryStateClass(telemetry.hertzbeat.state)); } },
    __csp_500: function() { with (this) { return (telemetryStateLabel(telemetry.hertzbeat.state)); } },
    __csp_501: function() { with (this) { loadHertzBeatResult() } },
    __csp_502: function() { with (this) { return (!telemetry.hertzbeatEventId); } },
    __csp_503: function() { with (this) { return (telemetry.hertzbeat.reason); } },
    __csp_504: function(item) { with (this) { return (item.event_id + ':' + item.source_node); } },
    __csp_505: function(item) { with (this) { return (item.event_id); } },
    __csp_506: function(item) { with (this) { return (item.source_node + ' · ' + fmtTime(item.occurred_at || item.observed_at)); } },
    __csp_507: function() { with (this) { clearChat() } },
    __csp_508: function() { with (this) { return (chat.messages.length === 0); } },
    __csp_509: function(msg) { with (this) { return (msg.role === 'user' ? 'flex justify-end' : 'flex flex-col items-start'); } },
    __csp_510: function(msg) { with (this) { return (msg.role === 'user'); } },
    __csp_511: function(msg) { with (this) { return (msg.content); } },
    __csp_512: function(msg) { with (this) { return (msg.role === 'assistant'); } },
    __csp_513: function(msg) { with (this) { return (!msg.content); } },
    __csp_514: function(msg) { with (this) { return (linkify(msg.content)); } },
    __csp_515: function(msg) { with (this) { return (msg.content && msg.sources && msg.sources.length); } },
    __csp_516: function(si) { with (this) { return (si); } },
    __csp_517: function(src) { with (this) { return (src.url); } },
    __csp_518: function(src) { with (this) { return (src.section || src.title); } },
    __csp_519: function(src) { with (this) { return ((src.similarity * 100).toFixed(0) + '%'); } },
    __csp_520: function(src) { with (this) { return (src.excerpt); } },
    __csp_521: function($event) { with (this) { if (!$event.shiftKey) sendChat() } },
    __csp_522: function() { with (this) { sendChat() } },
    __csp_523: function() { with (this) { return (chat.thinking || !chat.input.trim()); } },
    activeTab: 'kibana',
    mainView: 'alerts',
    settingsSection: 'models',
    autoRefresh: false,
    detTab: 'rules',
    _refreshTimer: null,
    identityRequired: false,

    health: { elasticsearch: null, litellm: null },
    telemetry: {
      logs: { state: 'unavailable', items: [], freshness: null },
      metrics: { state: 'unavailable', items: [], freshness: null },
      monitoring: { state: 'unavailable', items: [], freshness: null },
      hertzbeat: { state: 'unavailable', items: [], freshness: null, reason: 'exact_event_id_required' },
      hertzbeatEventId: '',
      sources: [
        { source: 'elastic-logs', state: 'unavailable', reason: 'source_view_unavailable' },
        { source: 'elastic-metrics', state: 'unavailable', reason: 'source_view_unavailable' },
        { source: 'monitoring', state: 'unavailable', reason: 'source_view_unavailable' },
        { source: 'hertzbeat', state: 'unavailable', reason: 'source_view_unavailable' },
        { source: 'windows-physical', state: 'not_applicable', reason: 'windows_inspection_not_authorized' },
      ],
    },

    timeRange: 'now-24h',
    searchQuery: '',
    hostFilter: '',
    hosts: [],
    _searchDebounce: null,
    kibana: {
      loading: false, loadingMore: false, error: null,
      alerts: [], total: 0,
      minSeverity: 'medium', nextCursor: '',
    },
    wazuh: {
      loading: false, loadingMore: false, error: null,
      alerts: [], total: 0,
      minLevel: 7, nextCursor: '',
    },
    sysmon: {
      loading: false, loadingMore: false, error: null,
      alerts: [], total: 0, nextCursor: '',
    },
    defender: {
      loading: false, loadingMore: false, error: null,
      alerts: [], total: 0, nextCursor: '',
      minSeverity: 'low',
    },
    chat: {
      messages: [], input: '', thinking: false,
    },
    _chatAbort: null,
    vulns: {
      loading: false, error: null, _loaded: false,
      agents: [], totalVulns: 0,
    },
    kev: {
      loading: false, pulling: false, error: null,
      pullMessage: null, pullError: false, status: null,
    },
    kevSettings: {
      auto_pull: true, frequency_hours: 24,
      alert_on_match: true, alert_on_overdue: true, ransomware_only: false,
      saving: false, message: null, error: false,
    },
    modelSettings: {
      activeModel: '', models: [], providers: {},
      saving: false, message: '', error: false,
    },
    localModels: {
      models: [], activeModel: '', status: {},
      switching: false, message: '', messageError: false,
      downloads: [], downloading: false,
      searchQuery: '', searching: false, searchResults: [], searchDone: false,
      downloadMessage: '', downloadError: false,
      _pollTimer: null,
    },

    docsIndex: {
      status: null, ingesting: false, message: '', error: false,
    },
    prebuilt: {
      loading: false, installing: false,
      status: null, message: '', error: false,
    },
    kevMatched: {
      loading: false, _loaded: false, items: [],
    },
    kibanaRules: {
      loading: false, rules: [], total: 0,
      page: 1, perPage: 50,
      search: '', enabledFilter: '', tagFilter: '',
      sortField: 'severity', sortOrder: 'asc',
      selected: new Set(),
      _loaded: false,
    },
    sigma: {
      converting: false, uploading: null,
      message: '', error: false,
      platforms: {}, totalRules: 0,
      _loaded: false,
      fileUploading: false, fileMessage: '', fileError: false,
      yamlUploading: false,
    },
    eaRules: {
      loading: false, error: null, _loaded: false,
      rules: [],
      uploading: false, uploadMessage: null, uploadError: false,
      showPasteModal: false, pasteYaml: '', pasteFilename: '',
      pasting: false, pasteMessage: null, pasteError: false,
      deleting: null,
      expanded: null, yamlCache: {}, loadingYaml: null,
    },


    async loadDocsStatus() {
      try {
        const r = await fetch('/api/docs/status');
        if (r.ok) this.docsIndex.status = await r.json();
      } catch(e) {}
    },

    async ingestDocs() {
      this.docsIndex.ingesting = true;
      this.docsIndex.message = '';
      this.docsIndex.error = false;
      try {
        const r = await fetch('/api/docs/ingest', { method: 'POST' });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
        this.docsIndex.message = `Done — ${data.chunks_indexed} chunks indexed`;
        await this.loadDocsStatus();
      } catch(e) {
        this.docsIndex.message = `Ingestion failed: ${e.message}`;
        this.docsIndex.error = true;
      } finally {
        this.docsIndex.ingesting = false;
      }
    },

    async loadPrebuiltStatus() {
      this.prebuilt.loading = true;
      try {
        const r = await fetch('/api/rules/prebuilt/status');
        if (r.ok) this.prebuilt.status = await r.json();
      } catch(e) { console.error('Prebuilt status failed:', e); }
      finally { this.prebuilt.loading = false; }
    },

    async installPrebuiltRules() {
      this.prebuilt.installing = true;
      this.prebuilt.message = '';
      this.prebuilt.error = false;
      try {
        const r = await fetch('/api/rules/prebuilt/install', { method: 'POST' });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
        const parts = [];
        if (data.rules_installed > 0) parts.push(`${data.rules_installed} rules installed`);
        if (data.rules_skipped > 0) parts.push(`${data.rules_skipped} skipped`);
        if (data.rules_failed > 0) parts.push(`${data.rules_failed} failed`);
        this.prebuilt.message = parts.length ? parts.join(', ') : 'All prebuilt rules are already installed';
        await this.loadPrebuiltStatus();
        await this.loadKibanaRules();
      } catch(e) {
        this.prebuilt.message = `Import failed: ${e.message}`;
        this.prebuilt.error = true;
      } finally {
        this.prebuilt.installing = false;
      }
    },

    async bulkActionByTag(action, tag) {
      const label = tag.replace('OS: ', '').replace('Sigma ', 'Sigma ');
      if (!confirm(`${action === 'enable' ? 'Enable' : 'Disable'} ALL ${label} rules?`)) return;
      this.kibanaRules.loading = true;
      try {
        const r = await fetch('/api/rules/kibana/bulk-action', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ action, query: `alert.attributes.tags:"${tag}"` }),
        });
        if (!r.ok) { const d = await r.json(); throw new Error(d.detail || `HTTP ${r.status}`); }
        await this.loadKibanaRules();
      } catch(e) {
        console.error('Bulk action failed:', e);
        alert(`Bulk action failed: ${e.message}`);
        this.kibanaRules.loading = false;
      }
    },

    async loadKibanaRules() {
      this.kibanaRules.loading = true;
      this.kibanaRules._loaded = true;
      this.kibanaRules.selected = new Set();
      try {
        const params = new URLSearchParams({
          page: this.kibanaRules.page,
          per_page: this.kibanaRules.perPage,
          sort_field: this.kibanaRules.sortField,
          sort_order: this.kibanaRules.sortOrder,
        });
        if (this.kibanaRules.search) params.set('q', this.kibanaRules.search);
        if (this.kibanaRules.enabledFilter) params.set('enabled', this.kibanaRules.enabledFilter);
        if (this.kibanaRules.tagFilter) params.set('tags', this.kibanaRules.tagFilter);
        const r = await fetch(`/api/rules/kibana?${params}`);
        if (!r.ok) throw new Error((await r.json()).detail || `HTTP ${r.status}`);
        const data = await r.json();
        this.kibanaRules.rules = data.rules;
        this.kibanaRules.total = data.total;
      } catch(e) {
        console.error('Failed to load Kibana rules:', e);
      } finally {
        this.kibanaRules.loading = false;
      }
    },

    sortKibanaRules(field) {
      if (this.kibanaRules.sortField === field) {
        this.kibanaRules.sortOrder = this.kibanaRules.sortOrder === 'asc' ? 'desc' : 'asc';
      } else {
        this.kibanaRules.sortField = field;
        this.kibanaRules.sortOrder = field === 'severity' || field === 'risk_score' ? 'desc' : 'asc';
      }
      this.kibanaRules.page = 1;
      this.loadKibanaRules();
    },

    toggleSelectAll() {
      if (this.kibanaRules.selected.size === this.kibanaRules.rules.length) {
        this.kibanaRules.selected = new Set();
      } else {
        this.kibanaRules.selected = new Set(this.kibanaRules.rules.map(r => r.id));
      }
    },

    toggleSelectRule(id) {
      const s = new Set(this.kibanaRules.selected);
      if (s.has(id)) s.delete(id); else s.add(id);
      this.kibanaRules.selected = s;
    },

    async toggleKibanaRule(rule) {
      const newState = !rule.enabled;
      rule.enabled = newState;
      try {
        const r = await fetch('/api/rules/kibana/toggle', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ ids: [rule.id], enabled: newState }),
        });
        if (!r.ok) rule.enabled = !newState;
      } catch(e) {
        rule.enabled = !newState;
      }
    },

    async bulkToggleKibanaRules(enabled) {
      const ids = [...this.kibanaRules.selected];
      if (!ids.length) return;
      if (!confirm(`${enabled ? 'Enable' : 'Disable'} ${ids.length} rules?`)) return;
      try {
        const r = await fetch('/api/rules/kibana/toggle', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ ids, enabled }),
        });
        if (r.ok) {
          this.kibanaRules.selected = new Set();
          await this.loadKibanaRules();
        }
      } catch(e) {
        console.error('Bulk toggle failed:', e);
      }
    },

    async loadSigmaStatus() {
      try {
        const r = await fetch('/api/rules/sigma/status');
        if (r.ok) {
          const data = await r.json();
          this.sigma.platforms = data.platforms;
          this.sigma.totalRules = data.total_rules;
          this.sigma._loaded = true;
        }
      } catch(e) {}
    },

    async sigmaConvert() {
      this.sigma.converting = true;
      this.sigma.message = '';
      this.sigma.error = false;
      try {
        const r = await fetch('/api/rules/sigma/convert', { method: 'POST' });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || 'Conversion failed');
        this.sigma.platforms = data.platforms;
        this.sigma.totalRules = data.total_rules;
        this.sigma.message = `Conversion complete: ${data.total_rules} rules across ${Object.keys(data.platforms).length} platforms`;
      } catch(e) {
        this.sigma.message = e.message;
        this.sigma.error = true;
      } finally {
        this.sigma.converting = false;
      }
    },

    async sigmaUpload(platform) {
      this.sigma.uploading = platform;
      this.sigma.message = '';
      this.sigma.error = false;
      try {
        const r = await fetch('/api/rules/sigma/upload', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ platform }),
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || 'Upload failed');
        const errCount = (data.errors || []).length;
        this.sigma.message = `${platform}: ${data.success_count} rules imported${errCount > 0 ? `, ${errCount} errors` : ''} (all disabled by default)`;
        await this.loadKibanaRules();
      } catch(e) {
        this.sigma.message = e.message;
        this.sigma.error = true;
      } finally {
        this.sigma.uploading = null;
      }
    },

    async sigmaUploadYaml(event) {
      const files = event.target.files;
      if (!files || !files.length) return;
      this.sigma.yamlUploading = true;
      this.sigma.fileMessage = '';
      this.sigma.fileError = false;
      const fd = new FormData();
      for (const f of files) fd.append('files', f);
      try {
        const r = await fetch('/api/rules/sigma/upload-yaml', { method: 'POST', body: fd });
        const data = await r.json();
        if (!r.ok) {
          const detail = data.detail || `HTTP ${r.status}`;
          throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
        }
        const errCount = (data.errors || []).length;
        this.sigma.fileMessage = `${data.success_count} rule${data.success_count !== 1 ? 's' : ''} imported from ${files.length} YAML file${files.length !== 1 ? 's' : ''}${errCount > 0 ? `, ${errCount} error${errCount !== 1 ? 's' : ''}` : ''} (all disabled by default)`;
        await this.loadKibanaRules();
      } catch(e) {
        this.sigma.fileMessage = `Upload failed: ${e.message}`;
        this.sigma.fileError = true;
      } finally {
        this.sigma.yamlUploading = false;
        event.target.value = '';
      }
    },

    async sigmaUploadFile(event) {
      const file = event.target.files[0];
      if (!file) return;
      this.sigma.fileUploading = true;
      this.sigma.fileMessage = '';
      this.sigma.fileError = false;
      const fd = new FormData();
      fd.append('file', file);
      try {
        const r = await fetch('/api/rules/sigma/upload-file', { method: 'POST', body: fd });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
        const errCount = (data.errors || []).length;
        this.sigma.fileMessage = `${data.success_count} rule${data.success_count !== 1 ? 's' : ''} imported from ${data.filename}${errCount > 0 ? `, ${errCount} error${errCount !== 1 ? 's' : ''}` : ''} (all disabled by default)`;
        await this.loadKibanaRules();
      } catch(e) {
        this.sigma.fileMessage = `Upload failed: ${e.message}`;
        this.sigma.fileError = true;
      } finally {
        this.sigma.fileUploading = false;
        event.target.value = '';
      }
    },

    async loadEaRules() {
      this.eaRules.loading = true;
      this.eaRules.error = null;
      try {
        const r = await fetch('/api/rules/elastalert');
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        this.eaRules.rules = data.rules;
        this.eaRules._loaded = true;
      } catch(e) {
        this.eaRules.error = `Failed to load rules: ${e.message}`;
      } finally {
        this.eaRules.loading = false;
      }
    },

    async uploadEaRules(event) {
      const files = event.target.files;
      if (!files || !files.length) return;
      this.eaRules.uploading = true;
      this.eaRules.uploadMessage = null;
      this.eaRules.uploadError = false;
      const fd = new FormData();
      for (const f of files) fd.append('files', f);
      try {
        const r = await fetch('/api/rules/elastalert/upload', { method: 'POST', body: fd });
        const data = await r.json();
        if (!r.ok) {
          const detail = data.detail || `HTTP ${r.status}`;
          throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
        }
        const saved = data.saved?.length || 0;
        const errs = data.errors?.length || 0;
        this.eaRules.uploadMessage = `Uploaded ${saved} rule${saved !== 1 ? 's' : ''}` +
          (errs ? ` (${errs} failed)` : '');
        this.eaRules.uploadError = saved === 0;
        await this.loadEaRules();
      } catch(e) {
        this.eaRules.uploadMessage = `Upload failed: ${e.message}`;
        this.eaRules.uploadError = true;
      } finally {
        this.eaRules.uploading = false;
        event.target.value = '';
      }
    },

    async pasteEaRule() {
      if (!this.eaRules.pasteYaml.trim()) return;
      this.eaRules.pasting = true;
      this.eaRules.pasteMessage = null;
      this.eaRules.pasteError = false;
      try {
        const r = await fetch('/api/rules/elastalert/paste', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            yaml_content: this.eaRules.pasteYaml,
            filename: this.eaRules.pasteFilename,
          }),
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
        this.eaRules.pasteMessage = `Saved as ${data.filename}`;
        this.eaRules.pasteError = false;
        this.eaRules.pasteYaml = '';
        this.eaRules.pasteFilename = '';
        await this.loadEaRules();
        setTimeout(() => { this.eaRules.showPasteModal = false; this.eaRules.pasteMessage = null; }, 1200);
      } catch(e) {
        this.eaRules.pasteMessage = `${e.message}`;
        this.eaRules.pasteError = true;
      } finally {
        this.eaRules.pasting = false;
      }
    },

    async deleteEaRule(filename) {
      if (!confirm(`Delete rule "${filename}"?`)) return;
      this.eaRules.deleting = filename;
      if (this.eaRules.expanded === filename) this.eaRules.expanded = null;
      try {
        const r = await fetch(`/api/rules/elastalert/${encodeURIComponent(filename)}`, { method: 'DELETE' });
        if (!r.ok) { const d = await r.json(); throw new Error(d.detail || `HTTP ${r.status}`); }
        delete this.eaRules.yamlCache[filename];
        await this.loadEaRules();
      } catch(e) {
        this.eaRules.uploadMessage = `Delete failed: ${e.message}`;
        this.eaRules.uploadError = true;
      } finally {
        this.eaRules.deleting = null;
      }
    },

    async toggleEaRule(filename) {
      if (this.eaRules.expanded === filename) {
        this.eaRules.expanded = null;
        return;
      }
      this.eaRules.expanded = filename;
      if (this.eaRules.yamlCache[filename] !== undefined) return;
      this.eaRules.loadingYaml = filename;
      try {
        const r = await fetch(`/api/rules/elastalert/${encodeURIComponent(filename)}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        this.eaRules.yamlCache[filename] = data.content;
      } catch(e) {
        this.eaRules.yamlCache[filename] = `# Error loading rule: ${e.message}`;
      } finally {
        this.eaRules.loadingYaml = null;
      }
    },

    get activeModelIsLocal() {
      const m = this.modelSettings.models.find(m => m.model_name === this.modelSettings.activeModel);
      return !m || m.provider === 'local' || m.provider === '';
    },
    newModel: {
      provider: 'local', model_name: '', litellm_model: '', api_key: '', api_base: '',
    },

    async init() {
      window.addEventListener('lme-identity-required', () => { this.identityRequired = true; });
      await Promise.all([this.loadHealth(), this.loadHosts(), this.loadKibana(), this.loadWazuh(), this.loadSysmon(), this.loadDefender(), this.loadModels(), this.loadLocalModels(), this.loadTelemetry()]);
    },

    telemetryStateLabel(state) {
      return ({
        fresh: 'Fresh', stale: 'Stale', empty: 'No data', filtered_empty: 'No matches',
        unavailable: 'Unavailable', not_applicable: 'N/A',
      })[state] || 'Unavailable';
    },

    telemetryStateClass(state) {
      if (state === 'fresh') return 'bg-green-900 text-green-300';
      if (state === 'stale') return 'bg-yellow-900 text-yellow-300';
      if (state === 'unavailable') return 'bg-red-900 text-red-300';
      return 'bg-surface-600 text-gray-300';
    },

    async loadTelemetry() {
      const views = ['logs', 'metrics', 'monitoring'];
      const endpoints = {
        logs: '/api/telemetry/logs',
        metrics: '/api/telemetry/metrics',
        monitoring: '/api/telemetry/monitoring',
      };
      await Promise.all(views.map(async view => {
        try {
          const response = await fetch(`${endpoints[view]}?time_from=${encodeURIComponent(this.timeRange)}`);
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          this.telemetry[view] = await response.json();
        } catch (e) {
          this.telemetry[view] = { state: 'unavailable', items: [], freshness: null, reason: e.message };
        }
      }));
      try {
        const response = await fetch(`/api/telemetry/sources?time_from=${encodeURIComponent(this.timeRange)}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        this.telemetry.sources = (await response.json()).sources || [];
      } catch (e) {
        this.telemetry.sources = [
          { source: 'elastic-logs', state: 'unavailable', reason: 'source_view_unavailable' },
          { source: 'elastic-metrics', state: 'unavailable', reason: 'source_view_unavailable' },
          { source: 'monitoring', state: 'unavailable', reason: 'source_view_unavailable' },
          { source: 'hertzbeat', state: 'unavailable', reason: 'source_view_unavailable' },
          { source: 'windows-physical', state: 'not_applicable', reason: 'windows_inspection_not_authorized' },
        ];
      }
    },

    async loadHertzBeatResult() {
      const eventId = this.telemetry.hertzbeatEventId;
      if (!/^[A-Za-z0-9_.:-]{1,256}$/.test(eventId)) {
        this.telemetry.hertzbeat = { state: 'unavailable', items: [], freshness: null, reason: 'invalid_event_id' };
        return;
      }
      try {
        const url = `/api/telemetry/hertzbeat-results?time_from=now-5m&event_id=${encodeURIComponent(eventId)}`;
        const response = await fetch(url);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        this.telemetry.hertzbeat = await response.json();
      } catch (e) {
        this.telemetry.hertzbeat = { state: 'unavailable', items: [], freshness: null, reason: e.message };
      }
    },

    async loadHealth() {
      try {
        const r = await fetch('/api/health');
        this.health = await r.json();
      } catch(e) {
        this.health = { elasticsearch: 'error', litellm: 'error' };
      }
    },

    _retryHealth(maxRetries, intervalMs) {
      let retries = 0;
      const timer = setInterval(async () => {
        await this.loadHealth();
        retries++;
        if (this.health.litellm === 'ok' || retries >= maxRetries) {
          clearInterval(timer);
        }
      }, intervalMs);
    },

    async loadKibana() {
      this.kibana.loading = true;
      this.kibana.error = null;
      this.kibana.nextCursor = '';
      try {
        const params = new URLSearchParams({
          min_severity: this.kibana.minSeverity,
          size: 50,
          time_from: this.timeRange,
          time_to: 'now',
        });
        if (this.searchQuery.trim()) params.set('q', this.searchQuery.trim());
        if (this.hostFilter) params.set('host', this.hostFilter);
        const r = await fetch(`/api/alerts/kibana?${params}`);
        if (!r.ok) {
          const err = await r.json();
          throw new Error(err.detail || `HTTP ${r.status}`);
        }
        const data = await r.json();
        this.kibana.alerts = data.alerts.map(a => ({
          ...a, _expanded: false, _analysis: null, _analyzing: false,
        }));
        this.kibana.total = data.total;
        this.kibana.nextCursor = data.next_cursor || '';
      } catch(e) {
        this.kibana.error = `Failed to load Kibana alerts: ${e.message}`;
      } finally {
        this.kibana.loading = false;
      }
    },

    async loadMoreKibana() {
      if (this.kibana.loadingMore || !this.kibana.nextCursor) return;
      this.kibana.loadingMore = true;
      try {
        const params = new URLSearchParams({
          min_severity: this.kibana.minSeverity,
          size: 50,
          time_from: this.timeRange,
          time_to: 'now',
          search_after: this.kibana.nextCursor,
        });
        if (this.searchQuery.trim()) params.set('q', this.searchQuery.trim());
        if (this.hostFilter) params.set('host', this.hostFilter);
        const r = await fetch(`/api/alerts/kibana?${params}`);
        if (!r.ok) return;
        const data = await r.json();
        const newAlerts = data.alerts.map(a => ({
          ...a, _expanded: false, _analysis: null, _analyzing: false,
        }));
        this.kibana.alerts.push(...newAlerts);
        this.kibana.nextCursor = data.next_cursor || '';
      } finally {
        this.kibana.loadingMore = false;
      }
    },

    async loadWazuh() {
      this.wazuh.loading = true;
      this.wazuh.error = null;
      this.wazuh.nextCursor = '';
      try {
        const params = new URLSearchParams({
          min_level: this.wazuh.minLevel,
          size: 50,
          time_from: this.timeRange,
          time_to: 'now',
        });
        if (this.searchQuery.trim()) params.set('q', this.searchQuery.trim());
        if (this.hostFilter) params.set('host', this.hostFilter);
        const r = await fetch(`/api/alerts/wazuh?${params}`);
        if (!r.ok) {
          const err = await r.json();
          throw new Error(err.detail || `HTTP ${r.status}`);
        }
        const data = await r.json();
        this.wazuh.alerts = data.alerts.map(a => ({
          ...a, _expanded: false, _analysis: null, _analyzing: false,
        }));
        this.wazuh.total = data.total;
        this.wazuh.nextCursor = data.next_cursor || '';
      } catch(e) {
        this.wazuh.error = `Failed to load Wazuh alerts: ${e.message}`;
      } finally {
        this.wazuh.loading = false;
      }
    },

    async loadMoreWazuh() {
      if (this.wazuh.loadingMore || !this.wazuh.nextCursor) return;
      this.wazuh.loadingMore = true;
      try {
        const params = new URLSearchParams({
          min_level: this.wazuh.minLevel,
          size: 50,
          time_from: this.timeRange,
          time_to: 'now',
          search_after: this.wazuh.nextCursor,
        });
        if (this.searchQuery.trim()) params.set('q', this.searchQuery.trim());
        if (this.hostFilter) params.set('host', this.hostFilter);
        const r = await fetch(`/api/alerts/wazuh?${params}`);
        if (!r.ok) return;
        const data = await r.json();
        const newAlerts = data.alerts.map(a => ({
          ...a, _expanded: false, _analysis: null, _analyzing: false,
        }));
        this.wazuh.alerts.push(...newAlerts);
        this.wazuh.nextCursor = data.next_cursor || '';
      } finally {
        this.wazuh.loadingMore = false;
      }
    },

    async loadSysmon() {
      this.sysmon.loading = true;
      this.sysmon.error = null;
      this.sysmon.nextCursor = '';
      try {
        const params = new URLSearchParams({
          size: 50,
          time_from: this.timeRange,
          time_to: 'now',
          filter_mode: 'severe',
        });
        if (this.searchQuery.trim()) params.set('q', this.searchQuery.trim());
        if (this.hostFilter) params.set('host', this.hostFilter);
        const r = await fetch(`/api/alerts/sysmon?${params}`);
        if (!r.ok) {
          const err = await r.json();
          throw new Error(err.detail || `HTTP ${r.status}`);
        }
        const data = await r.json();
        this.sysmon.alerts = data.alerts.map(a => ({
          ...a, _expanded: false, _analysis: null, _analyzing: false,
        }));
        this.sysmon.total = data.total;
        this.sysmon.nextCursor = data.next_cursor || '';
      } catch(e) {
        this.sysmon.error = `Failed to load Sysmon events: ${e.message}`;
      } finally {
        this.sysmon.loading = false;
      }
    },

    async loadMoreSysmon() {
      if (this.sysmon.loadingMore || !this.sysmon.nextCursor) return;
      this.sysmon.loadingMore = true;
      try {
        const params = new URLSearchParams({
          size: 50,
          time_from: this.timeRange,
          time_to: 'now',
          search_after: this.sysmon.nextCursor,
          filter_mode: 'severe',
        });
        if (this.searchQuery.trim()) params.set('q', this.searchQuery.trim());
        if (this.hostFilter) params.set('host', this.hostFilter);
        const r = await fetch(`/api/alerts/sysmon?${params}`);
        if (!r.ok) return;
        const data = await r.json();
        const newAlerts = data.alerts.map(a => ({
          ...a, _expanded: false, _analysis: null, _analyzing: false,
        }));
        this.sysmon.alerts.push(...newAlerts);
        this.sysmon.nextCursor = data.next_cursor || '';
      } finally {
        this.sysmon.loadingMore = false;
      }
    },

    async loadDefender() {
      this.defender.loading = true;
      this.defender.error = null;
      this.defender.nextCursor = '';
      try {
        const params = new URLSearchParams({
          size: 50,
          time_from: this.timeRange,
          time_to: 'now',
          min_severity: this.defender.minSeverity,
        });
        if (this.searchQuery.trim()) params.set('q', this.searchQuery.trim());
        if (this.hostFilter) params.set('host', this.hostFilter);
        const r = await fetch(`/api/alerts/defender?${params}`);
        if (!r.ok) {
          const err = await r.json();
          throw new Error(err.detail || `HTTP ${r.status}`);
        }
        const data = await r.json();
        this.defender.alerts = data.alerts.map(a => ({
          ...a, _expanded: false, _analysis: null, _analyzing: false,
        }));
        this.defender.total = data.total;
        this.defender.nextCursor = data.next_cursor || '';
      } catch(e) {
        this.defender.error = `Failed to load Defender events: ${e.message}`;
      } finally {
        this.defender.loading = false;
      }
    },

    async loadMoreDefender() {
      if (this.defender.loadingMore || !this.defender.nextCursor) return;
      this.defender.loadingMore = true;
      try {
        const params = new URLSearchParams({
          size: 50,
          time_from: this.timeRange,
          time_to: 'now',
          search_after: this.defender.nextCursor,
          min_severity: this.defender.minSeverity,
        });
        if (this.searchQuery.trim()) params.set('q', this.searchQuery.trim());
        if (this.hostFilter) params.set('host', this.hostFilter);
        const r = await fetch(`/api/alerts/defender?${params}`);
        if (!r.ok) return;
        const data = await r.json();
        const newAlerts = data.alerts.map(a => ({
          ...a, _expanded: false, _analysis: null, _analyzing: false,
        }));
        this.defender.alerts.push(...newAlerts);
        this.defender.nextCursor = data.next_cursor || '';
      } finally {
        this.defender.loadingMore = false;
      }
    },

    async loadHosts() {
      try {
        const r = await fetch('/api/alerts/hosts');
        if (r.ok) {
          const data = await r.json();
          this.hosts = data.hosts || [];
        }
      } catch(e) {}
    },

    async loadAll() {
      await Promise.all([this.loadHealth(), this.loadKibana(), this.loadWazuh(), this.loadSysmon(), this.loadDefender()]);
    },

    toggleAutoRefresh() {
      this.autoRefresh = !this.autoRefresh;
      if (this.autoRefresh) {
        this._refreshTimer = setInterval(() => this.loadAll(), 60000); // every 60s
      } else {
        clearInterval(this._refreshTimer);
      }
    },

    async analyzeAlert(alert, source) {
      alert._analyzing = true;
      alert._analysis = null;
      // send a minimal context (cap at 4kb) to keep the tiny model happy
      const rawSlice = JSON.parse(JSON.stringify(alert._raw));
      // strip noisy fields
      for (const k of ['message', 'event.original']) delete rawSlice[k];
      try {
        const r = await fetch('/api/analyze', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ alert: rawSlice, source }),
        });
        if (!r.ok) {
          const err = await r.json();
          alert._analysis = `Error: ${err.detail}`;
        } else {
          const data = await r.json();
          alert._analysis = data.analysis;
        }
      } catch(e) {
        alert._analysis = `Error: ${e.message}`;
      } finally {
        alert._analyzing = false;
      }
    },

    async sendChat() {
      const text = this.chat.input.trim();
      if (!text || this.chat.thinking) return;
      this.chat.input = '';
      this.chat.messages.push({ role: 'user', content: text });
      this.chat.thinking = true;
      this.$nextTick(() => this.scrollToMessage(this.chat.messages.length - 1));

      const endpoint = '/api/chat/rag/stream';
      const controller = new AbortController();
      this._chatAbort = controller;
      let idx = -1;

      try {
        const r = await fetch(endpoint, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          signal: controller.signal,
          body: JSON.stringify({
            messages: this.chat.messages.filter(m => m.role !== 'system'),
            stream: true,
          }),
        });
        if (!r.ok) {
          const err = await r.json();
          throw new Error(err.detail || `HTTP ${r.status}`);
        }

        // Add empty assistant message
        this.chat.messages.push({ role: 'assistant', content: '', sources: [], status: 'pending' });
        idx = this.chat.messages.length - 1;
        this.$nextTick(() => this.scrollToMessage(idx));

        const reader = r.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';
        let completed = false;
        stream: while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          const lines = buf.split('\n');
          buf = lines.pop();
          for (const line of lines) {
            if (!line.startsWith('data: ')) continue;
            const payload = line.slice(6).trim();
            if (payload === '[DONE]') {
              completed = true;
              this.chat.messages[idx].status = 'completed';
              break stream;
            }
            try {
              const obj = JSON.parse(payload);
              if (obj.sources) {
                this.chat.messages[idx].sources = obj.sources;
              }
              if (obj.content) {
                this.chat.messages[idx].content += obj.content;
              }
              if (obj.error) {
                throw new Error(obj.error);
              }
            } catch(error) {
              if (error instanceof SyntaxError) continue;
              throw error;
            }
          }
        }
        if (!completed) throw new Error('stream ended before completion marker');
      } catch(e) {
        const failure = `Incomplete response: ${e.message}`;
        if (idx >= 0) {
          const message = this.chat.messages[idx];
          message.status = 'failed';
          message.content = message.content
            ? `${message.content}\n\n[${failure}]`
            : failure;
        } else {
          this.chat.messages.push({ role: 'assistant', content: failure, sources: [], status: 'failed' });
        }
      } finally {
        this.chat.thinking = false;
        if (this._chatAbort === controller) this._chatAbort = null;
      }
    },

    scrollChat() {
      this.$nextTick(() => {
        const el = this.$refs.chatScroll;
        if (el) el.scrollTop = el.scrollHeight;
      });
    },
    scrollToMessage(idx) {
      this.$nextTick(() => {
        const el = this.$refs.chatScroll;
        if (!el) return;
        const msgs = el.querySelectorAll('[data-msg]');
        const target = msgs[idx];
        if (target) target.scrollIntoView({ block: 'start', behavior: 'smooth' });
        else el.scrollTop = el.scrollHeight;
      });
    },

    async loadModels() {
      try {
        const r = await fetch('/api/models');
        const data = await r.json();
        this.modelSettings.activeModel = data.active_model;
        this.modelSettings.models = data.models;
        this.modelSettings.providers = data.providers;
      } catch(e) {
        console.error('Failed to load models:', e);
      }
    },

    prefillModel() {
      const p = this.modelSettings.providers[this.newModel.provider];
      this.newModel.model_name = '';
      this.newModel.litellm_model = '';
      this.newModel.api_key = '';
      this.newModel.api_base = '';
      if (p && p.models && p.models.length) {
        this.newModel.litellm_model = p.models[0];
        this.newModel.model_name = p.models[0].split('/').pop();
      }
    },

    async addModel() {
      this.modelSettings.saving = true;
      this.modelSettings.message = '';
      try {
        const r = await fetch('/api/models', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(this.newModel),
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || 'Failed');
        this.modelSettings.message = data.message;
        this.modelSettings.error = false;
        this.newModel = { provider: this.newModel.provider, model_name: '', litellm_model: '', api_key: '', api_base: '' };
        await this.loadModels();
      } catch(e) {
        this.modelSettings.message = e.message;
        this.modelSettings.error = true;
      } finally {
        this.modelSettings.saving = false;
      }
    },

    async deleteModel(name) {
      if (!confirm(`Remove model "${name}"?`)) return;
      try {
        const r = await fetch(`/api/models/${encodeURIComponent(name)}`, { method: 'DELETE' });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || 'Failed');
        this.modelSettings.message = data.message;
        this.modelSettings.error = false;
        await this.loadModels();
      } catch(e) {
        this.modelSettings.message = e.message;
        this.modelSettings.error = true;
      }
    },

    async setActiveModel(name) {
      try {
        const r = await fetch('/api/models/active', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ model_name: name }),
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || 'Failed');
        this.modelSettings.activeModel = data.active_model;
        this.modelSettings.message = `Now using "${name}"`;
        this.modelSettings.error = false;
      } catch(e) {
        this.modelSettings.message = e.message;
        this.modelSettings.error = true;
      }
    },

    // ── Local model management ──────────────────────────────────────────
    async loadLocalModels() {
      try {
        const r = await fetch('/api/local-models');
        const data = await r.json();
        this.localModels.models = data.models;
        this.localModels.activeModel = data.active_model;
        this.localModels.status = data.status || {};
      } catch(e) {
        console.error('Failed to load local models:', e);
      }
      // Also check for in-progress downloads
      await this.checkDownloads();
    },

    async deleteLocalModel(filename) {
      if (!confirm(`Delete "${filename}"? This cannot be undone.`)) return;
      try {
        const r = await fetch(`/api/local-models/${encodeURIComponent(filename)}`, { method: 'DELETE' });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || 'Failed');
        this.localModels.models = this.localModels.models.filter(m => m.filename !== filename);
      } catch(e) {
        alert(`Delete failed: ${e.message}`);
      }
    },

    async switchLocalModel(filename) {
      if (!confirm(`Switch llama.cpp to "${filename}"?\n\nThis will restart the llama.cpp container. AI chat will be briefly unavailable.`)) return;
      this.localModels.switching = true;
      this.localModels.message = '';
      // Clear stale status so poll doesn't see old "ready"
      this.localModels.status = { status: 'switching', model: filename };
      try {
        const r = await fetch('/api/local-models/switch', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ model: filename }),
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || 'Failed');
        this.localModels.message = data.message;
        this.localModels.messageError = false;
        // Update the header model name immediately
        if (data.display_name) {
          this.modelSettings.activeModel = data.display_name;
        }
        // Poll for status updates while switching — pass filename so we know what to wait for
        this._pollLocalModelStatus(filename);
      } catch(e) {
        this.localModels.message = e.message;
        this.localModels.messageError = true;
        this.localModels.switching = false;
      }
    },

    async _fetchLocalModelsNoCache() {
      // Cache-busting fetch for status polling
      const r = await fetch('/api/local-models?_t=' + Date.now());
      return await r.json();
    },

    _pollLocalModelStatus(requestedFilename) {
      if (this.localModels._pollTimer) clearInterval(this.localModels._pollTimer);
      let attempts = 0;
      console.log('[model-switch] polling for:', requestedFilename);
      this.localModels._pollTimer = setInterval(async () => {
        attempts++;
        try {
          const data = await this._fetchLocalModelsNoCache();
          this.localModels.models = data.models;
          this.localModels.activeModel = data.active_model;
          this.localModels.status = data.status || {};
          const st = data.status?.status || '';
          const statusModel = data.status?.model || '';
          console.log(`[model-switch] poll #${attempts}: status=${st} model=${statusModel} wanted=${requestedFilename}`);
          // Only stop polling when status is "ready" for the model we actually requested
          const isForOurRequest = statusModel === requestedFilename;
          if (isForOurRequest && st === 'ready') {
            clearInterval(this.localModels._pollTimer);
            this.localModels._pollTimer = null;
            this.localModels.switching = false;
            this.localModels.message = `Now running ${requestedFilename}`;
            this.localModels.messageError = false;
            await this.loadModels();
            this._retryHealth(8, 3000);
          } else if (isForOurRequest && st === 'error') {
            clearInterval(this.localModels._pollTimer);
            this.localModels._pollTimer = null;
            this.localModels.switching = false;
            this.localModels.message = data.status?.error || 'Switch failed';
            this.localModels.messageError = true;
          } else if (attempts > 30) {
            clearInterval(this.localModels._pollTimer);
            this.localModels._pollTimer = null;
            this.localModels.switching = false;
            this.localModels.message = 'Switch is taking longer than expected. Refresh to check status.';
            this.localModels.messageError = true;
          }
        } catch(e) {
          console.error('[model-switch] poll error:', e);
        }
      }, 3000);
    },

    async searchModels() {
      this.localModels.searching = true;
      this.localModels.searchResults = [];
      this.localModels.searchDone = false;
      this.localModels.downloadMessage = '';
      try {
        const r = await fetch('/api/local-models/search', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ query: this.localModels.searchQuery }),
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || 'Search failed');
        this.localModels.searchResults = data.results;
        this.localModels.searchDone = true;
      } catch(e) {
        this.localModels.downloadMessage = e.message;
        this.localModels.downloadError = true;
        this.localModels.searchDone = true;
      } finally {
        this.localModels.searching = false;
      }
    },

    async downloadSearchResult(repoId, filename) {
      this.localModels.downloading = true;
      this.localModels.downloadMessage = '';
      this.localModels.downloadError = false;
      this.localModels._downloadingFilename = filename;
      try {
        const r = await fetch('/api/local-models/download', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ repo_id: repoId, filename }),
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || 'Failed');
        this.localModels.downloadMessage = `Downloading ${filename}...`;
        this.localModels.downloadError = false;
        this._pollDownloads(filename);
      } catch(e) {
        this.localModels.downloadMessage = e.message;
        this.localModels.downloadError = true;
        this.localModels.downloading = false;
      }
    },

    async checkDownloads() {
      try {
        const r = await fetch('/api/local-models/downloads');
        const data = await r.json();
        this.localModels.downloads = data.downloads;
        // Update message with progress if we have data
        if (data.downloads.length > 0) {
          const d = data.downloads[0];
          const sizeTxt = d.downloaded_mb >= 1024
            ? (d.downloaded_mb / 1024).toFixed(1) + ' GB'
            : d.downloaded_mb + ' MB';
          this.localModels.downloadMessage = `Downloading ${d.filename}... (${sizeTxt} so far)`;
        }
      } catch(e) {
        // ignore
      }
    },

    _pollDownloads(filename) {
      const timer = setInterval(async () => {
        await this.checkDownloads();
        if (this.localModels.downloads.length === 0) {
          clearInterval(timer);
          this.localModels.downloading = false;
          // Check if the file now exists in models list
          await this.loadLocalModels();
          const found = this.localModels.models.find(m => m.filename === filename);
          if (found) {
            const sizeTxt = found.size_mb >= 1024
              ? (found.size_mb / 1024).toFixed(1) + ' GB'
              : found.size_mb + ' MB';
            this.localModels.downloadMessage = `${filename} downloaded successfully (${sizeTxt}). You can now switch to it.`;
            this.localModels.downloadError = false;
          } else {
            this.localModels.downloadMessage = `Download of ${filename} may have failed — file not found.`;
            this.localModels.downloadError = true;
          }
        }
      }, 3000);
      setTimeout(() => {
        clearInterval(timer);
        if (this.localModels.downloading) {
          this.localModels.downloading = false;
          this.localModels.downloadMessage = 'Download timed out or is still running in the background. Refresh to check.';
          this.localModels.downloadError = true;
        }
      }, 30 * 60 * 1000);
    },

    async loadVulns() {
      this.vulns.loading = true;
      this.vulns.error = null;
      try {
        const r = await fetch('/api/vulnerabilities');
        if (!r.ok) {
          const err = await r.json();
          throw new Error(err.detail || `HTTP ${r.status}`);
        }
        const data = await r.json();
        this.vulns.agents = data.agents.map(a => ({
          ...a,
          _expanded: false,
        }));
        this.vulns.totalVulns = data.total_vulnerabilities;
        this.vulns._loaded = true;
      } catch(e) {
        this.vulns.error = `Failed to load vulnerabilities: ${e.message}`;
      } finally {
        this.vulns.loading = false;
      }
    },

    vulnDetail: { vulns: [], loading: false, sevFilter: '', agentId: null, total: 0, hasMore: false },
    _vulnPageSize: 50,

    async toggleAgentDetail(agent) {
      agent._expanded = !agent._expanded;
      if (agent._expanded) {
        this.vulnDetail = { vulns: [], loading: false, sevFilter: '', agentId: agent.agent_id, total: 0, hasMore: false };
        await this.loadAgentVulns(agent.agent_id, '', false);
      }
    },

    async loadAgentVulns(agentId, sevFilter, append) {
      const offset = append ? this.vulnDetail.vulns.length : 0;
      if (!append) {
        this.vulnDetail = { vulns: [], loading: true, sevFilter, agentId, total: 0, hasMore: false };
      } else {
        this.vulnDetail = { ...this.vulnDetail, loading: true };
      }
      try {
        const params = new URLSearchParams({ size: this._vulnPageSize, offset });
        if (sevFilter) params.set('severity', sevFilter);
        const r = await fetch(`/api/vulnerabilities/${agentId}?${params}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        const newVulns = append ? [...this.vulnDetail.vulns, ...data.vulnerabilities] : data.vulnerabilities;
        const hasMore = newVulns.length < data.total;
        this.vulnDetail = { vulns: newVulns, loading: false, sevFilter, agentId, total: data.total, hasMore };
      } catch(e) {
        console.error('Failed to load agent vulns:', e);
        this.vulnDetail = { ...this.vulnDetail, loading: false };
      }
    },

    onVulnScroll(ev) {
      const el = ev.target;
      if (this.vulnDetail.loading || !this.vulnDetail.hasMore) return;
      if (el.scrollTop + el.clientHeight >= el.scrollHeight - 100) {
        this.loadAgentVulns(this.vulnDetail.agentId, this.vulnDetail.sevFilter, true);
      }
    },

    clearChat() {
      this.chat.messages = [];
      this.chat.input = '';
    },

    async loadKevStatus() {
      this.kev.loading = true;
      this.kev.error = null;
      try {
        const r = await fetch('/api/kev/status');
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        this.kev.status = data;
        if (data.settings) {
          this.kevSettings = { ...this.kevSettings, ...data.settings };
        }
      } catch(e) {
        this.kev.error = `Failed to load KEV status: ${e.message}`;
      } finally {
        this.kev.loading = false;
      }
    },

    async loadKevMatched() {
      this.kevMatched.loading = true;
      this.kevMatched._loaded = true;
      try {
        const r = await fetch('/api/kev/matched');
        if (r.ok) {
          const data = await r.json();
          this.kevMatched.items = data.matched || [];
        }
      } catch(e) {
        console.error('Failed to load KEV matched:', e);
      } finally {
        this.kevMatched.loading = false;
      }
    },

    async kevPull() {
      this.kev.pulling = true;
      this.kev.pullMessage = null;
      this.kev.pullError = false;
      try {
        const r = await fetch('/api/kev/pull', { method: 'POST' });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
        this.kev.pullMessage = `Synced ${data.total} CVEs successfully.`;
        this.kev.pullError = false;
        await this.loadKevStatus();
      } catch(e) {
        this.kev.pullMessage = `Pull failed: ${e.message}`;
        this.kev.pullError = true;
      } finally {
        this.kev.pulling = false;
      }
    },

    async saveKevSettings() {
      this.kevSettings.saving = true;
      this.kevSettings.message = null;
      this.kevSettings.error = false;
      try {
        const r = await fetch('/api/settings/kev', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            auto_pull: this.kevSettings.auto_pull,
            frequency_hours: this.kevSettings.frequency_hours,
            alert_on_match: this.kevSettings.alert_on_match,
            alert_on_overdue: this.kevSettings.alert_on_overdue,
            ransomware_only: this.kevSettings.ransomware_only,
          }),
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
        this.kevSettings.message = 'Settings saved.';
        this.kevSettings.error = false;
      } catch(e) {
        this.kevSettings.message = `Save failed: ${e.message}`;
        this.kevSettings.error = true;
      } finally {
        this.kevSettings.saving = false;
      }
    },

    fmtTime(iso) {
      if (!iso) return '';
      try {
        const d = new Date(iso);
        const now = new Date();
        const diff = Math.floor((now - d) / 1000);
        if (diff < 60) return `${diff}s ago`;
        if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
        return d.toLocaleDateString();
      } catch(_) { return iso; }
    },

    severityBorder(sev) {
      return {
        critical: 'border-red-700',
        high:     'border-orange-700',
        medium:   'border-yellow-700',
        low:      'border-green-800',
        unknown:  'border-surface-600',
      }[sev] || 'border-surface-600';
    },

    severityBadge(sev) {
      return {
        critical: 'bg-red-900 text-red-300',
        high:     'bg-orange-900 text-orange-300',
        medium:   'bg-yellow-900 text-yellow-300',
        low:      'bg-green-900 text-green-300',
        unknown:  'bg-surface-700 text-gray-400',
      }[sev] || 'bg-surface-700 text-gray-400';
    },
  };
}

document.addEventListener("alpine:init", () => { Alpine.data("dashboard", dashboard); });
