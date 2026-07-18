import { Component, OnInit, signal, computed, AfterViewInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/services/api.service';
import { ToolResult } from '../../core/models';
import Chart from 'chart.js/auto';

type TabId = 'overview'|'subdomains'|'dns'|'http'|'vulns'|'wordpress'|'urls'|'tech'|'dorks'|'screenshots'|'ai';

@Component({
  selector: 'sg-results',
  standalone: true,
  imports: [CommonModule, RouterLink, FormsModule],
  templateUrl: './results.component.html',
  styleUrls: ['./results.component.scss'],
})
export class ResultsComponent implements OnInit, AfterViewInit {
  scanId!: string;
  results = signal<ToolResult[]>([]);
  loading = signal(true);
  activeTab = signal<TabId>('overview');
  lightbox: any = null;
  subQ = signal('');
  subStatus = signal('all');
  subPage = signal(0);
  httpQ = signal('');
  httpStatus = signal('all');
  vulnQ = signal('');
  vulnSev = signal('all');
  urlQ = signal('');
  urlSrc = signal('all');
  urlPage = signal(0);

  tabs = [
    {id:'overview' as TabId, label:'Overview'},
    {id:'subdomains' as TabId, label:'Subdomains'},
    {id:'dns' as TabId, label:'DNS & Assets'},
    {id:'http' as TabId, label:'HTTP & Ports'},
    {id:'vulns' as TabId, label:'Vulns'},
    {id:'wordpress' as TabId, label:'WordPress'},
    {id:'urls' as TabId, label:'URLs'},
    {id:'tech' as TabId, label:'Tech Stack'},
    {id:'dorks' as TabId, label:'Dorks'},
    {id:'screenshots' as TabId, label:'Screenshots'},
    {id:'ai' as TabId, label:'AI Analysis'},
  ];
  severities = ['all','critical','high','medium','low','info'];
  COMMON_PORTS = new Set([80,443,8080,8443,22,21,25,3389,3306,5432,6379,27017]);

  constructor(private route: ActivatedRoute, private api: ApiService) {}

  ngOnInit() {
    this.scanId = this.route.snapshot.paramMap.get('scanId')!;
    this.api.getResults(this.scanId).subscribe({
      next: rs => { this.results.set(rs); this.loading.set(false); this.initCharts(); },
      error: () => this.loading.set(false),
    });
  }
  ngAfterViewInit() { setTimeout(() => this.initCharts(), 200); }

  setTab(t: TabId) {
    this.activeTab.set(t);
    setTimeout(() => this.initCharts(), 100);
  }

  // ── Data extractors ─────────────────────────────────────────────
  private byCategory(cat: string) { return this.results().filter(r => r.category === cat).flatMap(r => r.data); }
  private byTool(tool: string)    { return this.results().filter(r => r.tool === tool).flatMap(r => r.data); }

  subdomains = computed(() => {
    const all = this.byCategory('subdomain');
    const httpx = this.byTool('httpx');
    const httpxMap = new Map(httpx.map(h => [h['host'] || '', h]));
    const alive = new Set(this.byTool('dnsx').map((d: any) => (d['host'] || '').split(' ')[0]));
    const seen = new Map<string, any>();
    all.forEach((s: any) => {
      const h = s['host']; if (!h) return;
      if (!seen.has(h)) {
        const hx = httpxMap.get(h) || {};
        seen.set(h, { host:h, source:s['source'], alive:alive.has(h)||!!hx['url'],
          status:hx['status'], title:hx['title'], tech:hx['tech'] || [] });
      }
    });
    return [...seen.values()];
  });

  aliveCount   = computed(() => this.subdomains().filter((s: any) => s['alive']).length);
  ports        = computed(() => this.byTool('naabu'));
  vulns        = computed(() => this.byTool('nuclei'));
  urls         = computed(() => this.results().filter(r => r.category === 'url').flatMap(r => r.data));
  screenshots  = computed(() => this.byTool('gowitness'));
  dorks        = computed(() => this.byTool('google_dorks'));
  wpFindings   = computed(() => this.byTool('wpscan'));
  // One AI report per in-scope asset (each scanned domain produces its own row).
  aiReports    = computed(() => this.byTool('ai_analysis'));
  dnsRecords   = computed(() => this.byTool('dns_records'));
  zoneResults  = computed(() => this.byTool('zone_transfer'));
  whoisData    = computed(() => { const d = this.byTool('whois')[0]; return d ? d['whois'] : 'No WHOIS data'; });
  asnRanges    = computed(() => this.byTool('asnmap'));
  httpResults  = computed(() => this.byTool('httpx'));

  techInventory = computed(() => {
    const map = new Map<string, Set<string>>();
    this.httpResults().forEach((h: any) => {
      (h['tech'] || []).forEach((t: string) => {
        const k = t.split(':')[0].trim();
        if (!map.has(k)) map.set(k, new Set());
        if (h['host']) map.get(k)!.add(h['host']);
      });
    });
    return [...map.entries()].map(([name,hosts]) => ({name,count:hosts.size})).sort((a,b)=>b.count-a.count);
  });
  maxTech   = computed(() => this.techInventory()[0]?.count || 1);
  critHigh  = computed(() => this.vulns().filter((v: any) => ['critical','high'].includes(v['severity'])).length);
  topVulns  = computed(() => [...this.vulns()].sort((a: any,b: any) => this.sevRank(a)-this.sevRank(b)).slice(0,5));

  filteredSubs = computed(() => {
    let rows = this.subdomains();
    const q = this.subQ().trim().toLowerCase();
    const status = this.subStatus();

    if (q) rows = rows.filter((x: any) => (x['host'] || '').toLowerCase().includes(q));
    if (status === 'alive') rows = rows.filter((x: any) => x['alive']);
    if (status === 'dead') rows = rows.filter((x: any) => !x['alive']);

    return rows;
  });
  pagedSubs = computed(() => {
    const page = this.subPage();
    return this.filteredSubs().slice(page * 100, (page + 1) * 100);
  });
  totalSubPages = computed(() => Math.ceil(this.filteredSubs().length / 100));

  filteredHttp = computed(() => {
    let rows = this.httpResults();
    const q = this.httpQ().trim().toLowerCase();
    const status = this.httpStatus();

    if (q) {
      rows = rows.filter((x: any) =>
        (x['url'] || '').toLowerCase().includes(q) ||
        (x['title'] || '').toLowerCase().includes(q) ||
        (x['host'] || '').toLowerCase().includes(q));
    }

    if (status !== 'all') {
      rows = rows.filter((x: any) => {
        const sc = Number(x['status']);
        if (status === '2xx') return sc >= 200 && sc < 300;
        if (status === '3xx') return sc >= 300 && sc < 400;
        if (status === '4xx') return sc >= 400 && sc < 500;
        if (status === '5xx') return sc >= 500;
        return true;
      });
    }

    return rows;
  });

  filteredVulns = computed(() => {
    let rows = this.vulns();
    const sev = this.vulnSev();
    const q = this.vulnQ().trim().toLowerCase();

    if (sev !== 'all') rows = rows.filter((x: any) => (x['severity'] || '').toLowerCase() === sev);
    if (q) {
      rows = rows.filter((x: any) =>
        (x['name'] || '').toLowerCase().includes(q) ||
        (x['template_id'] || '').toLowerCase().includes(q) ||
        (x['matched_at'] || '').toLowerCase().includes(q) ||
        (x['host'] || '').toLowerCase().includes(q));
    }

    return [...rows].sort((a: any, b: any) => this.sevRank(a) - this.sevRank(b));
  });

  filteredUrls = computed(() => {
    let rows = this.urls();
    const source = this.urlSrc();
    const q = this.urlQ().trim().toLowerCase();

    if (source !== 'all') rows = rows.filter((x: any) => x['source'] === source);
    if (q) rows = rows.filter((x: any) => (x['url'] || '').toLowerCase().includes(q));

    return rows;
  });

  urlSources = computed(() => {
    const m = new Map<string, number>();
    this.urls().forEach((u: any) => { const s = u['source']||'unknown'; m.set(s,(m.get(s)||0)+1); });
    return [...m.entries()].map(([name,count])=>({name,count}));
  });

  portSummary = computed(() => {
    const m = new Map<number,number>();
    this.ports().forEach((p: any) => m.set(p['port'],(m.get(p['port'])||0)+1));
    return [...m.entries()].map(([port,count])=>({port,count})).sort((a,b)=>b.count-a.count);
  });


  // ── Filter setters: reset pagination whenever a filter changes ─────────
  setSubQ(value: string) { this.subQ.set(value); this.subPage.set(0); }
  setSubStatus(value: string) { this.subStatus.set(value); this.subPage.set(0); }
  setHttpQ(value: string) { this.httpQ.set(value); }
  setHttpStatus(value: string) { this.httpStatus.set(value); }
  setVulnQ(value: string) { this.vulnQ.set(value); }
  setVulnSev(value: string) { this.vulnSev.set(value); }
  setUrlQ(value: string) { this.urlQ.set(value); this.urlPage.set(0); }
  setUrlSrc(value: string) { this.urlSrc.set(value); this.urlPage.set(0); }
  totalUrlPages(): number { return Math.ceil(this.filteredUrls().length / 200); }

  // ── Helper methods ──────────────────────────────────────────────
  sevRank(f: any): number {
    const m: any = {critical:0,high:1,medium:2,low:3,info:4,unknown:5};
    return m[(f['severity']||'unknown').toLowerCase()] ?? 5;
  }
  sevCount(s: string): number {
    if (s === 'all') return 0;
    return this.vulns().filter((v: any) => v['severity'] === s).length;
  }
  tabCount(t: TabId): number {
    const m: Record<TabId,number> = {
      overview:0, subdomains:this.subdomains().length, dns:this.dnsRecords().length,
      http:this.httpResults().length, vulns:this.vulns().length, wordpress:this.wpFindings().length,
      urls:this.urls().length, tech:this.techInventory().length, dorks:this.dorks().length,
      screenshots:this.screenshots().length, ai:this.aiReports().length
    };
    return m[t] || 0;
  }
  wpSites(): number {
    return new Set(this.wpFindings().map((f: any) => f['url']).filter(Boolean)).size;
  }
  isCommonPort(p: number): boolean { return this.COMMON_PORTS.has(p); }
  portClass(p: number): string { return 'port-chip' + (this.isCommonPort(p) ? ' common' : ''); }
  statusBadge(code: number): string {
    if (code >= 500) return 'badge-5xx';
    if (code >= 400) return 'badge-4xx';
    if (code >= 300) return 'badge-3xx';
    return 'badge-2xx';
  }

  // ── Export methods (no arrow functions in template) ─────────────
  exportSubdomains()  { this.exportTxt(this.filteredSubs().map((s: any) => s['host']), 'subdomains.txt'); }
  exportHttpUrls()    { this.exportTxt(this.filteredHttp().map((h: any) => h['url']), 'alive_urls.txt'); }
  exportAllUrls()     { this.exportTxt(this.filteredUrls().map((u: any) => u['url']), 'urls.txt'); }
  exportDorks()       { this.exportTxt(this.dorks().map((d: any) => d['dork']), 'google_dorks.txt'); }
  exportAiReport(report: any) {
    const md = report?.['markdown'] || '';
    const name = (report?.['domain'] || 'asset').toString().replace(/[^a-z0-9.-]+/gi, '_');
    this.exportTxt([md], `ai_analysis_${name}.md`);
  }

  copy(text: string)  { navigator.clipboard.writeText(text).catch(() => {}); }
  copyItem(item: any, key: string) { this.copy(item[key] || ''); }

  artifactSrc(item: any): string {
    return item?.['path'] ? this.api.artifactUrl(this.scanId, item['path']) : '';
  }

  artifactPath(path: string | undefined): string {
    return path ? this.api.artifactUrl(this.scanId, path) : '#';
  }

  exportTxt(lines: string[], fname: string) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([lines.filter(Boolean).join('\n')], {type:'text/plain'}));
    a.download = fname; a.click();
  }
  exportJson() {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify(this.results(),null,2)], {type:'application/json'}));
    a.download = `scan-${this.scanId.slice(0,8)}.json`; a.click();
  }

  techBarWidth(count: number): string { return ((count / this.maxTech()) * 100) + '%'; }

  initCharts() {
    const sevCanvas  = document.getElementById('chart-sev')  as HTMLCanvasElement;
    const toolCanvas = document.getElementById('chart-tools') as HTMLCanvasElement;
    if (sevCanvas && !(sevCanvas as any)._chartInstance) {
      const counts = this.severities.filter(s => s !== 'all').map(s => this.sevCount(s));
      const c = new Chart(sevCanvas, {
        type:'doughnut',
        data:{ labels:['Critical','High','Medium','Low','Info'],
          datasets:[{data:counts, backgroundColor:['#ff4757','#ff8c42','#ffc22a','#00bcd4','#78909c'],
          borderColor:'#0b1628', borderWidth:3}]},
        options:{responsive:true, maintainAspectRatio:false, cutout:'62%',
          plugins:{legend:{position:'right', labels:{color:'#c4d4eb', font:{size:11}}}}}
      });
      (sevCanvas as any)._chartInstance = c;
    }
    if (toolCanvas && !(toolCanvas as any)._chartInstance) {
      const r = this.results().slice(0,12);
      const c = new Chart(toolCanvas, {
        type:'bar',
        data:{ labels:r.map(x => x.tool),
          datasets:[{label:'Results', data:r.map(x => x.count),
          backgroundColor:'rgba(0,232,122,.5)', borderColor:'#00e87a', borderWidth:1, borderRadius:4}]},
        options:{indexAxis:'y', responsive:true, maintainAspectRatio:false,
          plugins:{legend:{display:false}},
          scales:{x:{grid:{color:'#1a2e4a'}, ticks:{color:'#60789a'}}, y:{ticks:{color:'#c4d4eb'}}}}
      });
      (toolCanvas as any)._chartInstance = c;
    }
  }
}
