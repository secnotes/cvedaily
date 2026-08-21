/* Daily CVE report renderer.
 *
 * The HTML is a static shell; this script fetches the day's JSON
 * (window.DAILY_CVE_DATA_URL) and renders CVE cards client-side in
 * batches as the user scrolls, so the DOM only ever holds roughly a
 * viewport's worth of cards instead of all ~3000. Filtering operates on
 * the data array and re-renders, keeping the exact semantics of the old
 * server-rendered page (mutually exclusive severity/status/vendor
 * filters, cvss-N / epss-N dynamic filters).
 */
(function () {
    'use strict';

    // ---------- shared state ----------
    let CVE_DATA = [];        // raw cves from the daily JSON
    let AI_DATA = null;       // normalized AI curation from the daily JSON
    let cveLookup = new Map();// id -> cve (for AI view enrichment)
    let currentView = 'original';
    const BATCH = 60;         // cards appended per render pass

    // ---------- history (date switcher) state ----------
    let manifestDates = [];   // available dates, newest first (data/index.json)
    let currentDate = null;   // 'YYYY-MM-DD' currently displayed

    function dataUrlFor(dateStr) {
        return 'data/' + dateStr.slice(0, 4) + '/cves_' + dateStr.replace(/-/g, '') + '.json';
    }

    // Per-view render state: items (cve objects / AI flat items),
    // how many are in the DOM, and the grid elements.
    const viewState = {
        original: { items: [], rendered: 0, grid: null, status: null, sentinel: null },
        ai: { items: [], rendered: 0, grid: null, status: null, sentinel: null }
    };

    window.activeFilters = {
        severities: [],    // CVSS severity filters (critical, high, medium, low)
        status: [],        // Status filters (cisa, epss, modified, published, ...)
        vendors: []        // Vendor filters (mutually exclusive)
    };

    // Current UI language ('en' default; 'zh' opts into the Chinese UI)
    let currentLang = localStorage.getItem('cve-lang') === 'zh' ? 'zh' : 'en';
    // Pick a string by current language: t('English', '中文')
    function t(en, zh) { return currentLang === 'zh' ? zh : en; }

    // ---------- theme / language / layout controls (unchanged behavior) ----------
    function toggleTheme() {
        const root = document.documentElement;
        const currentTheme = root.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

        root.classList.add('theme-switching');
        root.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);

        const remove = () => root.classList.remove('theme-switching');
        requestAnimationFrame(() => requestAnimationFrame(remove));
        setTimeout(remove, 100);
    }

    function toggleLang() {
        setLang(currentLang === 'zh' ? 'en' : 'zh');
    }
    function setLang(lang) {
        currentLang = lang;
        document.documentElement.classList.toggle('lang-mode-zh', lang === 'zh');
        localStorage.setItem('cve-lang', lang);
        // Status lines are set via textContent at render time; refresh them
        refreshStatusLines();
    }

    function scrollToTop() {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    window.addEventListener('scroll', function () {
        document.getElementById('back-to-top').classList.toggle('show', window.scrollY > 600);
    });

    // Mobile sidebar overlay (FAB toggles; backdrop click closes)
    function toggleSidebar(force) {
        const sidebar = document.querySelector('.sidebar');
        const backdrop = document.getElementById('sidebar-backdrop');
        const open = typeof force === 'boolean' ? force : !sidebar.classList.contains('open');
        sidebar.classList.toggle('open', open);
        backdrop.classList.toggle('show', open);
        document.body.style.overflow = open ? 'hidden' : '';
    }

    // ---------- text helpers ----------
    function esc(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    }

    // Markdown code blocks -> HTML. Input is RAW text; escaping happens
    // here (the old pipeline escaped descriptions server-side and let
    // non-code text through unescaped - a latent injection vector).
    function renderDescription(text) {
        if (!text) {
            return '<span class="lang-en">No description provided by the CNA yet - check NVD details via the link below.</span>'
                + '<span class="lang-zh">CNA 暂未提供描述 - 可点击下方 NVD 链接查看详情。</span>';
        }
        let s = esc(text);
        s = s.replace(/```(\w*)\n?([\s\S]*?)```/g, function (m, lang, code) {
            return '<pre><code class="' + lang + '">' + code.trim() + '</code></pre>';
        });
        s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
        return s;
    }

    function severityOf(cvss) {
        if (cvss >= 9.0) return 'critical';
        if (cvss >= 7.0) return 'high';
        if (cvss >= 4.0) return 'medium';
        return 'low';
    }

    function fmtEpss(v) { return Number(v).toFixed(3); }

    // ---------- CVE card rendering (DOM parity with the old template) ----------
    function cveCardHtml(cve) {
        const id = cve.id;
        const cvss = cve.cvss || 0;
        const epss = cve.epss || 0;
        const kev = !!cve.kev;
        const modified = !!cve.mod;
        const pub = cve.pub || '';
        const upd = cve.upd || '';
        const vendors = cve.vendors || [];
        const sev = severityOf(cvss);

        let metrics =
            '<span class="metric-tag tag-cvss" onclick="applySingleFilterByCVSS(' + cvss + ')">🛡️ CVSS: ' + cvss.toFixed(1) + '</span>';
        if (epss > 0) {
            metrics += '<span class="metric-tag tag-epss" onclick="applySingleFilterByEPSS(' + fmtEpss(epss) + ')">📈 EPSS: ' + fmtEpss(epss) + '</span>';
        }
        if (kev) {
            metrics += '<span class="metric-tag tag-cisa" onclick="toggleStatusFilter(\'cisa\')">🇺🇸 CISA KEV</span>';
        }
        if (modified) {
            metrics += '<span class="metric-tag tag-exp" onclick="toggleStatusFilter(\'modified\')">🔄 <span class="lang-en">Recently Updated</span><span class="lang-zh">最近更新</span></span>';
        } else {
            metrics += '<span class="metric-tag tag-cisa" onclick="toggleStatusFilter(\'published\')">🆕 <span class="lang-en">New Entry</span><span class="lang-zh">新条目</span></span>';
        }

        let vendorTags = '';
        if (vendors.length) {
            vendorTags = '<div class="cve-vendors"><strong><span class="lang-en">Vendors:</span><span class="lang-zh">厂商:</span></strong>'
                + vendors.map(function (v) {
                    return '<span class="cve-vendor-tag" data-vendor="' + esc(v) + '">' + esc(v) + '</span>';
                }).join('')
                + '</div>';
        }

        let links =
            '<div class="link-item"><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + encodeURIComponent(id) + '" target="_blank" class="link-btn">📝 MITRE CVE</a></div>'
            + '<div class="link-item"><a href="https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(id) + '" target="_blank" class="link-btn">🔍 <span class="lang-en">NVD Details</span><span class="lang-zh">NVD 详情</span></a></div>';
        if (epss > 0) {
            links += '<div class="link-item"><a href="https://epss.cyentia.com/?cve=' + encodeURIComponent(id) + '" target="_blank" class="link-btn">📊 <span class="lang-en">EPSS Score</span><span class="lang-zh">EPSS 评分</span></a></div>';
        }

        let meta = '<strong><span class="lang-en">Published:</span><span class="lang-zh">发布:</span></strong> ' + (pub ? esc(pub.slice(0, 10)) : 'Unknown');
        if (upd && upd !== pub) {
            meta += ' | <strong><span class="lang-en">Modified:</span><span class="lang-zh">更新:</span></strong> ' + esc(upd.slice(0, 10));
        }

        return '<div class="cve-card filtered-in" id="cve-' + esc(id.replace(/-/g, '_')) + '"'
            + ' data-cvss="' + cvss + '"'
            + ' data-epss="' + epss + '"'
            + ' data-cisa="' + (kev ? 'true' : 'false') + '"'
            + ' data-modified="' + (modified ? 'True' : 'False') + '"'
            + ' data-vendors="' + esc(vendors.join(',')) + '">'
            + '<div class="cve-header">'
            + '<div class="cve-id">' + esc(id) + '</div>'
            + '<div class="cve-severity severity-' + sev + '">' + sev.charAt(0).toUpperCase() + sev.slice(1) + '</div>'
            + '</div>'
            + '<div class="cve-body">'
            + '<div class="cve-description">' + renderDescription(cve.d) + '</div>'
            + '<div class="cve-content-group">'
            + '<div class="cve-metrics">' + metrics + '</div>'
            + vendorTags
            + '<div class="cve-links">' + links + '</div>'
            + '<div class="cve-meta">' + meta + '</div>'
            + '</div></div></div>';
    }

    // ---------- AI view rendering ----------
    function buildAiItems() {
        const items = [];
        if (!AI_DATA || !AI_DATA.categories) return items;
        items.push({ type: 'summary' });
        AI_DATA.categories.forEach(function (cat) {
            if (!cat.items || !cat.items.length) return;
            items.push({ type: 'header', cat: cat });
            cat.items.forEach(function (entry) {
                items.push({ type: 'card', cat: cat, entry: entry, cve: cveLookup.get(entry.id) });
            });
        });
        return items;
    }

    function aiItemHtml(item) {
        if (item.type === 'summary') {
            const ai = AI_DATA;
            return '<div class="ai-summary">'
                + '<h3>🤖 <span class="lang-en">AI Analysis Summary</span><span class="lang-zh">AI智能分析摘要</span>'
                + ' <span class="model-badge">' + esc(ai.model) + '</span></h3>'
                + '<div class="ai-summary-text"><span class="lang-en">' + esc(ai.summary_en) + '</span><span class="lang-zh">' + esc(ai.summary_zh) + '</span></div>'
                + '<div class="ai-summary-meta">'
                + '<span><span class="lang-en">Analysis date:</span><span class="lang-zh">分析日期:</span> ' + esc(ai.date) + '</span>'
                + '<span><span class="lang-en">Curated:</span><span class="lang-zh">精选漏洞:</span> ' + ai.curated_count + '</span>'
                + '<span><span class="lang-en">Analyzed:</span><span class="lang-zh">候选漏洞:</span> ' + ai.analyzed + '</span>'
                + '</div></div>';
        }
        if (item.type === 'header') {
            const cat = item.cat;
            return '<div class="ai-category" id="ai-category-' + esc(cat.id) + '">'
                + '<h3 class="ai-category-title">' + cat.icon
                + ' <span class="lang-en">' + esc(cat.en) + '</span><span class="lang-zh">' + esc(cat.zh) + '</span>'
                + ' (' + cat.items.length + ')</h3></div>';
        }

        // card
        const entry = item.entry, cve = item.cve || {};
        const cvss = cve.cvss || 0;
        const epss = cve.epss || 0;
        let description = cve.d || 'No description provided yet; see NVD for details.';
        if (description.length > 200) description = description.slice(0, 200) + '...';
        const vendors = cve.vendors || [];
        let vendorsStr = vendors.slice(0, 5).join(', ') || 'N/A';
        if (vendors.length > 5) vendorsStr += ' (+' + (vendors.length - 5) + ')';

        const sev = cvss >= 9.0 ? 'Critical' : cvss >= 7.0 ? 'High' : cvss >= 4.0 ? 'Medium' : 'Low';
        const sevClass = cvss >= 9.0 ? 'severity-critical' : cvss >= 7.0 ? 'severity-high' : cvss >= 4.0 ? 'severity-medium' : 'severity-low';

        let reason = '';
        const reasonEn = entry.reason_en || entry.reason || '';
        const reasonZh = entry.reason_zh || entry.reason || '';
        if (reasonEn || reasonZh) {
            reason = '<div class="ai-cve-reason">💡 '
                + '<span class="lang-en"><strong>Why it matters:</strong> ' + esc(reasonEn) + '</span>'
                + '<span class="lang-zh"><strong>推荐理由:</strong> ' + esc(reasonZh) + '</span>'
                + '</div>';
        }

        return '<div class="ai-cve-card">'
            + '<div class="ai-cve-header">'
            + '<a href="https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(entry.id) + '" target="_blank" class="ai-cve-id">' + esc(entry.id) + '</a>'
            + '<span class="cve-severity ' + sevClass + '">' + sev + ' (' + cvss.toFixed(1) + ')</span>'
            + '</div>'
            + '<div class="ai-cve-description">' + esc(description) + '</div>'
            + '<div class="ai-cve-meta">'
            + '<span>🏢 ' + esc(vendorsStr) + '</span>'
            + (cve.kev ? '<span>🇺🇸 CISA KEV</span>' : '')
            + (epss > 0 ? '<span>📈 EPSS: ' + fmtEpss(epss) + '</span>' : '')
            + '</div>'
            + reason
            + '</div>';
    }

    // Note: AI category cards are appended INTO the category header div
    // created above, so the flat item list is rendered as:
    //   header div -> [its cards] ... next header div -> ...
    // buildAiItems interleaves them; the renderer opens a container on a
    // header item and appends following card items into it.
    function aiItemHtmlOpen(item) { return aiItemHtml(item); }

    // ---------- batch rendering ----------
    function renderMore(view) {
        const st = viewState[view];
        if (!st.grid) return;
        const end = Math.min(st.rendered + BATCH, st.items.length);
        if (end <= st.rendered) return;

        const frag = document.createDocumentFragment();
        const tpl = document.createElement('template');
        for (let i = st.rendered; i < end; i++) {
            if (view === 'original') {
                tpl.innerHTML = cveCardHtml(st.items[i]);
                frag.appendChild(tpl.content.firstChild);
            } else {
                const item = st.items[i];
                if (item.type === 'header') {
                    tpl.innerHTML = aiItemHtml(item);
                    frag.appendChild(tpl.content.firstChild);
                    st._openCat = frag.lastChild;
                } else if (item.type === 'summary') {
                    tpl.innerHTML = aiItemHtml(item);
                    frag.appendChild(tpl.content.firstChild);
                } else {
                    tpl.innerHTML = aiItemHtml(item);
                    // Cards belonging to a category go inside its div so
                    // scrollToCategory lands on header+cards together
                    (st._openCat || st.grid).appendChild(tpl.content.firstChild);
                }
            }
        }
        st.grid.appendChild(frag);
        st.rendered = end;
        updateStatusLine(view);
    }

    function resetView(view, items) {
        const st = viewState[view];
        st.items = items;
        st.rendered = 0;
        st._openCat = null;
        st.grid.innerHTML = '';
        renderMore(view);
        // Tall viewports (or a small filtered set) may still leave the
        // sentinel on-screen - keep filling
        requestAnimationFrame(checkSentinels);
    }

    function updateStatusLine(view) {
        const st = viewState[view];
        if (!st.status) return;
        if (view === 'ai' && !AI_DATA) {
            st.status.textContent = '';
            return;
        }
        if (st.items.length === 0) {
            st.status.classList.remove('error');
            st.status.textContent = t('No CVEs match the current filters.', '没有符合当前筛选条件的漏洞。');
            return;
        }
        st.status.classList.remove('error');
        st.status.textContent = t(
            'Showing ' + st.rendered + ' of ' + st.items.length + ' vulnerabilities (scroll for more)',
            '已显示 ' + st.rendered + ' / ' + st.items.length + ' 个漏洞（滚动加载更多）');
    }

    function refreshStatusLines() {
        updateStatusLine('original');
        updateStatusLine('ai');
    }

    // ---------- per-date DOM rebuilds (history switcher) ----------
    function setText(id, text) {
        const el = document.getElementById(id);
        if (el) el.textContent = text;
    }

    function updateStatsDom(stats) {
        setText('stat-total', stats.total != null ? stats.total : CVE_DATA.length);
        setText('stat-high-risk', stats.high_risk != null ? stats.high_risk : '');
        setText('stat-cisa', stats.cisa != null ? stats.cisa : '');
        setText('stat-epss', stats.epss != null ? stats.epss : '');
        setText('filter-critical', 'Critical (' + (stats.critical || 0) + ')');
        setText('filter-high', 'High (' + (stats.high || 0) + ')');
        setText('filter-medium', 'Medium (' + (stats.medium || 0) + ')');
        setText('filter-low', 'Low (' + (stats.low || 0) + ')');

        const mod = document.getElementById('filter-modified');
        if (mod) mod.innerHTML = '🔄 <span class="lang-en">Recently Modified (' + (stats.modified || 0) + ')</span><span class="lang-zh">最近修改 (' + (stats.modified || 0) + ')</span>';
        const pub = document.getElementById('filter-published');
        if (pub) pub.innerHTML = '🆕 <span class="lang-en">Newly Published (' + (stats.published || 0) + ')</span><span class="lang-zh">新发布 (' + (stats.published || 0) + ')</span>';
    }

    // Vendor DOM id must match updateSelectedFiltersHighlight's lookup
    function vendorDomId(name) {
        return name.replace(/[^a-zA-Z0-9]/g, '_');
    }

    function rebuildVendorList() {
        const section = document.getElementById('vendor-filter-section');
        if (!section) return;

        const counts = {};
        CVE_DATA.forEach(c => (c.vendors || []).forEach(v => {
            counts[v] = (counts[v] || 0) + 1;
        }));
        const sorted = Object.keys(counts).map(v => [v, counts[v]])
            .sort((a, b) => b[1] - a[1]);
        const top = sorted.slice(0, 10);
        const rest = sorted.slice(10);

        let html = '<div class="filter-title">🏢 <span class="lang-en">Filter by Vendor</span><span class="lang-zh">按厂商筛选</span></div>'
            + '<ul class="filter-list" id="vendor-filter-list">';
        const li = (v, n, extra) =>
            '<li class="filter-item' + extra + '" id="filter-vendor-' + vendorDomId(v)
            + '" data-vendor="' + esc(v) + '" style="display:' + (extra ? 'none' : 'block') + '">'
            + esc(v) + ' (' + n + ')</li>';
        top.forEach(([v, n]) => { html += li(v, n, ''); });
        rest.forEach(([v, n]) => { html += li(v, n, ' extra-vendor'); });
        html += '</ul>';
        if (rest.length) {
            html += '<button class="show-more-btn" onclick="toggleMoreVendors()" id="show-more-btn">'
                + t('Show More Vendors (' + rest.length + ' more)', '显示更多厂商 (还有 ' + rest.length + ')')
                + '</button>';
        }
        section.innerHTML = html;
        moreVendorsShown = false;
    }

    function rebuildAiSidebar() {
        const toggle = document.getElementById('view-toggle');
        const aiSidebar = document.getElementById('ai-sidebar');
        const navList = document.getElementById('ai-nav-list');

        if (!AI_DATA) {
            if (toggle) toggle.style.display = 'none';
            if (aiSidebar) aiSidebar.style.display = 'none';
            return;
        }

        if (toggle) toggle.style.display = '';
        if (aiSidebar) aiSidebar.style.display = '';
        if (navList) {
            navList.innerHTML = (AI_DATA.categories || []).map(cat =>
                '<li onclick="scrollToCategory(\'' + esc(cat.id) + '\')">' + cat.icon
                + ' <span class="lang-en">' + esc(cat.en) + '</span>'
                + '<span class="lang-zh">' + esc(cat.zh) + '</span> (' + cat.items.length + ')</li>'
            ).join('');
        }
        setText('ai-stat-date', AI_DATA.date || '-');
        setText('ai-stat-count', AI_DATA.curated_count || 0);
        setText('ai-stat-analyzed', AI_DATA.analyzed || 0);
        setText('ai-stat-model', AI_DATA.model || '-');
    }

    // ---------- filter engine (semantics ported verbatim) ----------
    function cveMatchesFilters(cve) {
        const cvss = cve.cvss || 0;
        const epss = cve.epss || 0;

        // CVSS severity filter (mutually exclusive)
        if (window.activeFilters.severities.length > 0) {
            const severity = window.activeFilters.severities[0];
            switch (severity) {
                case 'critical': if (cvss < 9.0) return false; break;
                case 'high': if (cvss < 7.0 || cvss >= 9.0) return false; break;
                case 'medium': if (cvss < 4.0 || cvss >= 7.0) return false; break;
                case 'low': if (cvss >= 4.0 || cvss === 0) return false; break;
            }
        }

        // Status filter (mutually exclusive)
        if (window.activeFilters.status.length > 0) {
            const filter = window.activeFilters.status[0];
            switch (filter) {
                case 'cisa': if (!cve.kev) return false; break;
                case 'epss': if (epss < 0.01) return false; break;
                case 'modified': if (!cve.mod) return false; break;
                case 'published': if (cve.mod) return false; break;
                case 'high-risk': if (cvss <= 7.0) return false; break;
                default:
                    if (filter.indexOf('cvss-') === 0) {
                        if (cvss < parseFloat(filter.slice(5))) return false;
                    } else if (filter.indexOf('epss-') === 0) {
                        if (epss < parseFloat(filter.slice(5))) return false;
                    }
                    break;
            }
        }

        // Vendor filter (mutually exclusive)
        if (window.activeFilters.vendors.length > 0) {
            const vendor = window.activeFilters.vendors[0];
            if ((cve.vendors || []).indexOf(vendor) === -1) return false;
        }
        return true;
    }

    function applyAllFilters() {
        const visible = CVE_DATA.filter(cveMatchesFilters);
        resetView('original', visible);
        updateActiveFiltersDisplay();
        return visible.length;
    }

    // ---------- filter UI callbacks (same API as before) ----------
    function toggleStatusFilter(filterType) {
        const index = window.activeFilters.status.indexOf(filterType);
        if (index > -1) {
            window.activeFilters.status = [];
        } else {
            window.activeFilters.status = [filterType];
        }
        const count = applyAllFilters();
        updateSelectedFiltersHighlight();
        showFilterCount(count);
    }

    function toggleVendorFilter(vendor) {
        const index = window.activeFilters.vendors.indexOf(vendor);
        if (index > -1) {
            window.activeFilters.vendors = [];
        } else {
            window.activeFilters.vendors = [vendor];
        }
        const count = applyAllFilters();
        updateSelectedFiltersHighlight();
        showFilterCount(count);
    }

    function applySingleFilter(filterType) {
        if (filterType === 'all') {
            clearAllFilters();
        } else if (filterType === 'high-risk') {
            window.activeFilters.status = ['high-risk'];
            const count = applyAllFilters();
            updateSelectedFiltersHighlight();
            showFilterCount(count);
        } else if (filterType === 'cisa') {
            window.activeFilters.status = ['cisa'];
            const count = applyAllFilters();
            updateSelectedFiltersHighlight();
            showFilterCount(count);
        } else if (filterType === 'epss') {
            window.activeFilters.status = ['epss'];
            const count = applyAllFilters();
            updateSelectedFiltersHighlight();
            showFilterCount(count);
        }
    }

    function applySingleFilterByCVSS(minScore) {
        window.activeFilters = {
            status: ['cvss-' + minScore],
            severities: [],
            vendors: []
        };
        applyAllFilters();
    }

    function applySingleFilterBySeverity(severity) {
        const index = window.activeFilters.severities.indexOf(severity);
        if (index > -1) {
            window.activeFilters.severities = [];
        } else {
            window.activeFilters.severities = [severity];
        }
        const count = applyAllFilters();
        updateSelectedFiltersHighlight();
        showFilterCount(count);
    }

    function applySingleFilterByEPSS(minScore) {
        window.activeFilters = {
            status: ['epss-' + minScore],
            severities: [],
            vendors: []
        };
        applyAllFilters();
    }

    function clearAllFilters() {
        window.activeFilters = {
            severities: [],
            status: [],
            vendors: []
        };
        applyAllFilters();
        updateSelectedFiltersHighlight();
    }

    // Show filter count toast
    function showFilterCount(count) {
        const existingToast = document.querySelector('.filter-count-toast');
        if (existingToast) existingToast.remove();

        const toast = document.createElement('div');
        toast.className = 'filter-count-toast';
        toast.textContent = t(count + ' CVE' + (count !== 1 ? 's' : '') + ' found', '找到 ' + count + ' 个漏洞');
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 2000);
    }

    // Update the display of active filters
    function updateActiveFiltersDisplay() {
        const activeFiltersDiv = document.getElementById('active-filters');
        if (!activeFiltersDiv) return;

        let filterText = [];
        for (let severity of window.activeFilters.severities) {
            filterText.push(t('Severity: ', '严重度: ') + t(severity, { critical: '严重', high: '高危', medium: '中危', low: '低危' }[severity] || severity));
        }
        for (let status of window.activeFilters.status) {
            switch (status) {
                case 'cisa': filterText.push('CISA KEV'); break;
                case 'epss': filterText.push(t('High EPSS', '高 EPSS')); break;
                case 'modified': filterText.push(t('Recently Modified', '最近修改')); break;
                case 'published': filterText.push(t('Newly Published', '新发布')); break;
                case 'high-risk': filterText.push(t('High Risk (CVSS > 7.0)', '高危 (CVSS > 7.0)')); break;
                default:
                    if (status.indexOf('cvss-') === 0) {
                        filterText.push('CVSS ≥ ' + parseFloat(status.slice(5)));
                    } else if (status.indexOf('epss-') === 0) {
                        filterText.push('EPSS ≥ ' + parseFloat(status.slice(5)));
                    }
                    break;
            }
        }
        for (let vendor of window.activeFilters.vendors) {
            filterText.push(t('Vendor: ', '厂商: ') + vendor);
        }
        if (filterText.length === 0) {
            activeFiltersDiv.textContent = t('None', '无');
        } else {
            activeFiltersDiv.textContent = filterText.join(', ');
        }
    }

    // Update highlight for selected filters in sidebar
    function updateSelectedFiltersHighlight() {
        document.querySelectorAll('.filter-item').forEach(item => item.classList.remove('selected'));
        document.querySelectorAll('.filter-metric-tag').forEach(tag => tag.classList.remove('selected'));

        window.activeFilters.severities.forEach(severity => {
            const element = document.getElementById('filter-' + severity);
            if (element) element.classList.add('selected');
        });

        window.activeFilters.status.forEach(status => {
            let elementId = null;
            switch (status) {
                case 'cisa': elementId = 'filter-cisa'; break;
                case 'epss': elementId = 'filter-epss'; break;
                case 'modified': elementId = 'filter-modified'; break;
                case 'published': elementId = 'filter-published'; break;
                case 'high-risk': elementId = 'filter-high-risk'; break;
                // dynamic cvss-N / epss-N filters have no sidebar element
            }
            if (elementId) {
                const element = document.getElementById(elementId);
                if (element) element.classList.add('selected');
            }
        });

        if (window.activeFilters.vendors.length > 0) {
            const vendor = window.activeFilters.vendors[0];
            const vendorElement = document.getElementById('filter-vendor-' + vendorDomId(vendor));
            if (vendorElement) vendorElement.classList.add('selected');
        }
    }

    // Toggle more vendors
    let moreVendorsShown = false;
    function toggleMoreVendors() {
        const extraVendors = document.querySelectorAll('.extra-vendor');
        const showMoreBtn = document.getElementById('show-more-btn');

        if (!moreVendorsShown) {
            extraVendors.forEach(item => { item.style.display = 'block'; });
            showMoreBtn.textContent = t('Show Less Vendors', '收起厂商列表');
            moreVendorsShown = true;
        } else {
            extraVendors.forEach(item => { item.style.display = 'none'; });
            // Count read from the DOM: no server-side interpolation here
            showMoreBtn.textContent = t('Show More Vendors (' + extraVendors.length + ' more)',
                '显示更多厂商 (还有 ' + extraVendors.length + ')');
            moreVendorsShown = false;
        }
    }

    // ---------- view switching ----------
    function switchView(view) {
        const originalView = document.getElementById('original-view');
        const aiView = document.getElementById('ai-view');
        const originalSidebar = document.getElementById('original-sidebar');
        const aiSidebar = document.getElementById('ai-sidebar');
        const buttons = document.querySelectorAll('.view-toggle-btn');

        buttons.forEach(btn => btn.classList.remove('active'));

        if (view === 'original') {
            originalView.classList.remove('hidden');
            aiView.classList.remove('active');
            originalSidebar.classList.remove('hidden');
            if (aiSidebar) aiSidebar.classList.add('hidden');
            buttons[1].classList.add('active');
            currentView = 'original';
        } else {
            if (!AI_DATA) return; // no AI data for this day
            originalView.classList.add('hidden');
            aiView.classList.add('active');
            originalSidebar.classList.add('hidden');
            if (aiSidebar) aiSidebar.classList.remove('hidden');
            buttons[0].classList.add('active');
            currentView = 'ai';
            if (viewState.ai.items.length === 0 && AI_DATA) {
                resetView('ai', buildAiItems());
            }
        }
    }

    // Scroll to a specific AI category. The AI view renders lazily in
    // scroll-triggered batches, so the target header may not be in the
    // DOM yet when the user clicks a category they never scrolled to.
    // Render further batches synchronously until it exists (stops as
    // soon as the header appears - categories beyond it stay lazy).
    function scrollToCategory(safeId) {
        const st = viewState.ai;
        let el = document.getElementById('ai-category-' + safeId);
        while (!el && st.rendered < st.items.length) {
            renderMore('ai');
            el = document.getElementById('ai-category-' + safeId);
        }
        if (el) {
            el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    // ---------- vendor clicks (event delegation) ----------
    // Cards and the sidebar vendor list are created/destroyed
    // dynamically, so per-element onclick attributes would need
    // re-binding; one listener covers them all.
    document.addEventListener('click', function (e) {
        const el = e.target.closest('[data-vendor]');
        if (el && el.dataset.vendor) {
            toggleVendorFilter(el.dataset.vendor);
        }
    });

    // ---------- data loading / date switching ----------
    function applyData(data) {
        CVE_DATA = data.cves || [];
        AI_DATA = data.ai || null;
        cveLookup = new Map(CVE_DATA.map(c => [c.id, c]));
        currentDate = data.date || currentDate;

        updateStatsDom(data.stats || {});
        rebuildVendorList();
        rebuildAiSidebar();

        // Reset filter + view state for the new day
        window.activeFilters = { severities: [], status: [], vendors: [] };
        updateActiveFiltersDisplay();
        updateSelectedFiltersHighlight();
        resetView('original', CVE_DATA);
        viewState.ai.items = [];
        if (viewState.ai.grid) viewState.ai.grid.innerHTML = '';
        if (currentView === 'ai' && !AI_DATA) switchView('original');
        else if (currentView === 'ai' && AI_DATA) switchView('ai'); // rebuild lazily

        document.title = 'Daily CVE Report - ' + currentDate;
        const dateEl = document.getElementById('report-date');
        if (dateEl) dateEl.textContent = currentDate;
        const genEl = document.getElementById('generated-time');
        if (genEl) genEl.textContent = data.generated || '';
        const rawLink = document.getElementById('raw-data-link');
        if (rawLink) rawLink.setAttribute('href', dataUrlFor(currentDate));
    }

    async function loadDate(dateStr) {
        const st = viewState.original;
        try {
            const resp = await fetch(dataUrlFor(dateStr));
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            const data = await resp.json();
            applyData(data);
            setDateSelect(dateStr);
            return true;
        } catch (err) {
            st.status.classList.add('error');
            st.status.textContent = t(
                'Failed to load CVE data for ' + dateStr + ' (' + err.message + ')',
                '加载 ' + dateStr + ' 的 CVE 数据失败 (' + err.message + ')');
            return false;
        }
    }

    // Pick a date from the switcher dropdown
    function switchDate(dateStr) {
        if (!dateStr || dateStr === currentDate) return;
        loadDate(dateStr).then(ok => {
            if (ok) location.hash = dateStr;
        });
    }

    // Prev/next arrows walk the manifest. It is stored newest-first, so
    // "previous day" (delta -1, i.e. older) is a HIGHER index - flip the
    // sign, otherwise both arrows index outside the array and no-op.
    function stepDate(delta) {
        const idx = manifestDates.indexOf(currentDate);
        if (idx === -1) return;
        const next = manifestDates[idx - delta];
        if (next) switchDate(next);
    }

    function setDateSelect(dateStr) {
        const sel = document.getElementById('date-select');
        if (sel) sel.value = dateStr;
        const prev = document.getElementById('date-prev');
        const next = document.getElementById('date-next');
        const idx = manifestDates.indexOf(dateStr);
        if (prev) prev.disabled = idx === -1 || idx >= manifestDates.length - 1;
        if (next) next.disabled = idx <= 0;
    }

    async function loadData() {
        const st = viewState.original;
        try {
            // Manifest first: it defines what the switcher can offer and
            // which date to show (URL hash wins, else today)
            let initialDate = null;
            try {
                const mResp = await fetch('data/index.json');
                if (mResp.ok) {
                    const manifest = await mResp.json();
                    manifestDates = manifest.dates || [];
                }
            } catch (e) { /* manifest optional - switcher just stays empty */ }

            const sel = document.getElementById('date-select');
            if (sel && manifestDates.length) {
                sel.innerHTML = manifestDates
                    .map(d => '<option value="' + d + '">' + d + '</option>')
                    .join('');
            }

            const hashDate = decodeURIComponent(location.hash.replace(/^#/, ''));
            if (manifestDates.length && manifestDates.indexOf(hashDate) !== -1) {
                initialDate = hashDate;
            } else {
                // today = the date the shell was generated for
                const m = (window.DAILY_CVE_DATA_URL || '').match(/cves_(\d{8})\.json/);
                initialDate = m ? m[1].replace(/(^\d{4})(\d{2})(\d{2}$)/, '$1-$2-$3') : null;
            }

            const resp = await fetch(initialDate ? dataUrlFor(initialDate) : window.DAILY_CVE_DATA_URL);
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            const data = await resp.json();
            applyData(data);
            if (initialDate && initialDate !== currentDate) {
                // keep the URL consistent with what's on screen
                location.hash = initialDate;
            }
            setDateSelect(currentDate);
        } catch (err) {
            st.status.classList.add('error');
            st.status.textContent = t(
                'Failed to load CVE data (' + err.message + '). Raw JSON: ' + window.DAILY_CVE_DATA_URL,
                'CVE 数据加载失败 (' + err.message + ')。原始 JSON: ' + window.DAILY_CVE_DATA_URL);
        }
    }

    // Back/forward buttons walk visited dates via the hash
    window.addEventListener('hashchange', function () {
        const d = decodeURIComponent(location.hash.replace(/^#/, ''));
        if (d && d !== currentDate && manifestDates.indexOf(d) !== -1) {
            loadDate(d);
        }
    });

    // ---------- bootstrap ----------
    document.addEventListener('DOMContentLoaded', function () {
        viewState.original.grid = document.getElementById('cve-grid');
        viewState.original.status = document.getElementById('original-status');
        viewState.original.sentinel = document.getElementById('original-sentinel');
        viewState.ai.grid = document.getElementById('ai-content');
        viewState.ai.status = document.getElementById('ai-status');
        viewState.ai.sentinel = document.getElementById('ai-sentinel');

        // Infinite scroll: render the next batch when a sentinel nears
        // the viewport. Hidden views never intersect, so both views can
        // share one observer. A scroll-event fallback below covers
        // browsers without IntersectionObserver (and headless testing,
        // where the compositor never runs and IO callbacks stay silent).
        if ('IntersectionObserver' in window) {
            const io = new IntersectionObserver(function (entries) {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const view = entry.target.id === 'original-sentinel' ? 'original' : 'ai';
                        renderMore(view);
                    }
                });
            }, { rootMargin: '800px' });
            io.observe(viewState.original.sentinel);
            io.observe(viewState.ai.sentinel);
        }

        let scrollTick = false;
        window.addEventListener('scroll', function () {
            if (scrollTick) return;
            scrollTick = true;
            requestAnimationFrame(function () {
                scrollTick = false;
                checkSentinels();
            });
        });

        loadData();
    });

    // Fallback infinite-scroll check: fill any view whose sentinel is
    // within ~one screen of the viewport.
    function checkSentinels() {
        ['original', 'ai'].forEach(function (view) {
            const st = viewState[view];
            if (!st.sentinel || st.rendered >= st.items.length) return;
            if (st.grid && st.grid.offsetParent === null &&
                document.getElementById(view === 'original' ? 'original-view' : 'ai-view').classList.contains('hidden')) {
                return; // view not visible
            }
            const rect = st.sentinel.getBoundingClientRect();
            if (rect.top < window.innerHeight + 800) {
                renderMore(view);
            }
        });
    }

    // Expose the onclick API the shell / rendered cards reference
    Object.assign(window, {
        toggleTheme, toggleLang, setLang, scrollToTop, toggleSidebar,
        toggleStatusFilter, toggleVendorFilter, applySingleFilter,
        applySingleFilterByCVSS, applySingleFilterBySeverity,
        applySingleFilterByEPSS, clearAllFilters, toggleMoreVendors,
        switchView, scrollToCategory, applyAllFilters,
        switchDate, stepDate
    });
})();
