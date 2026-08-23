import { CommonModule } from '@angular/common';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { PortfolioAsset, PortfolioFinding, PortfolioResponse } from '../../core/models';
import { ApiService } from '../../core/services/api.service';

type PortfolioMode = 'assets' | 'findings' | 'changes';

@Component({
  selector: 'sg-portfolio',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <div class="eyebrow">Attack surface</div>
          <h1 class="page-title">{{title()}}</h1>
          <p class="page-sub">{{subtitle()}}</p>
        </div>
        <button class="btn btn-outline btn-sm" (click)="load()" [disabled]="loading()">Refresh</button>
      </div>

      @if (data(); as portfolio) {
        <div class="stat-grid portfolio-stats">
          <div class="stat-card accent"><div class="stat-label">Known assets</div><div class="stat-value green">{{portfolio.summary.assets}}</div></div>
          <div class="stat-card" [class.danger]="portfolio.summary.critical_high > 0"><div class="stat-label">Critical / high</div><div class="stat-value" [class.red]="portfolio.summary.critical_high > 0">{{portfolio.summary.critical_high}}</div></div>
          <div class="stat-card"><div class="stat-label">Open findings</div><div class="stat-value cyan">{{portfolio.summary.findings}}</div></div>
          <div class="stat-card"><div class="stat-label">Inventory coverage</div><div class="stat-value">{{coverage()}}%</div><div class="stat-note">{{portfolio.summary.programs_with_inventory}} of {{portfolio.summary.projects}} programs</div></div>
        </div>

        <div class="filter-bar">
          <div class="filter-search"><span class="filter-icon">⌕</span><input [ngModel]="query()" (ngModelChange)="query.set($event)" [placeholder]="searchPlaceholder()" aria-label="Search" /></div>
          @if (mode() === 'assets') {
            <select class="filter-select" [ngModel]="assetType()" (ngModelChange)="assetType.set($event)" aria-label="Asset type">
              <option value="all">All asset types</option>
              @for (type of assetTypes(); track type) { <option [value]="type">{{type}}</option> }
            </select>
          }
          @if (mode() === 'findings') {
            <select class="filter-select" [ngModel]="severity()" (ngModelChange)="severity.set($event)" aria-label="Severity">
              <option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option>
            </select>
          }
          <span class="filter-count">{{visibleCount()}} results</span>
        </div>

        @if (mode() === 'assets') {
          <div class="card data-card"><div class="table-wrap"><table>
            <thead><tr><th>Asset</th><th>Type</th><th>Program</th><th>Observed state</th><th>Findings</th><th>Last seen</th></tr></thead>
            <tbody>
              @for (asset of filteredAssets(); track asset.project_id + asset.id) {
                <tr class="click-row" tabindex="0" (click)="selectedAsset.set(asset)" (keydown.enter)="selectedAsset.set(asset)">
                  <td><div class="asset-name">{{asset.value}}</div><div class="source-line">{{asset.sources.join(', ')}}</div></td>
                  <td><span class="badge badge-tool">{{asset.type}}</span></td>
                  <td><a [routerLink]="['/projects', asset.project_id]" (click)="$event.stopPropagation()">{{asset.project_name}}</a></td>
                  <td>{{asset.states.join(', ') || 'observed'}}</td>
                  <td><span class="risk-count" [class.has-risk]="asset.finding_count > 0">{{asset.finding_count}}</span></td>
                  <td>{{asset.last_seen | date:'MMM d, HH:mm'}}</td>
                </tr>
              } @empty { <tr><td colspan="6"><div class="empty-state"><h3>No assets match</h3><p>Adjust the filters or complete an assessment to build inventory.</p></div></td></tr> }
            </tbody>
          </table></div></div>
        } @else if (mode() === 'findings') {
          <div class="finding-list">
            @for (finding of filteredFindings(); track finding.project_id + finding.id) {
              <article class="finding-card" [class]="finding.severity">
                <div class="finding-main"><span class="badge badge-{{finding.severity}}">{{finding.severity}}</span><div><h3>{{finding.title}}</h3><div class="source-line">{{finding.asset_value}} · {{finding.tool}}</div></div></div>
                <div class="finding-actions"><a [routerLink]="['/projects', finding.project_id]">{{finding.project_name}}</a><a class="btn btn-outline btn-sm" [routerLink]="['/scan', finding.scan_id, 'results']">Evidence</a></div>
              </article>
            } @empty { <div class="card"><div class="empty-state"><h3>No findings match</h3><p>No unresolved findings meet the selected filters.</p></div></div> }
          </div>
        } @else {
          <div class="change-grid">
            @for (change of filteredChanges(); track change.project_id + change.scan_id) {
              <article class="card change-card">
                <div class="change-head"><div><a class="change-title" [routerLink]="['/projects', change.project_id]">{{change.project_name}}</a><div class="source-line">{{change.created_at | date:'medium'}}</div></div><a class="btn btn-outline btn-sm" [routerLink]="['/scan', change.scan_id, 'results']">Review</a></div>
                <div class="change-counts"><span class="delta added">+{{change.added_assets.length}} assets</span><span class="delta removed">−{{change.removed_assets.length}} assets</span><span class="delta changed">{{change.changed_assets.length}} changed</span><span class="delta risk">+{{change.new_findings.length}} findings</span><span class="delta resolved">{{change.resolved_findings.length}} resolved</span></div>
              </article>
            } @empty { <div class="card"><div class="empty-state"><h3>No changes available</h3><p>Complete two assessments for a program to establish drift.</p></div></div> }
          </div>
        }
      } @else if (loading()) {
        <div class="empty-state"><div class="spinner-sm"></div><span>Building portfolio view…</span></div>
      } @else {
        <div class="card"><div class="empty-state"><h3>Portfolio unavailable</h3><p>{{error()}}</p><button class="btn btn-primary" (click)="load()">Try again</button></div></div>
      }
    </div>

    @if (selectedAsset(); as asset) {
      <div class="drawer-backdrop" (click)="selectedAsset.set(null)"></div>
      <aside class="asset-drawer" role="dialog" aria-modal="true" aria-label="Asset details">
        <div class="drawer-head"><div><span class="badge badge-tool">{{asset.type}}</span><h2>{{asset.value}}</h2><a [routerLink]="['/projects', asset.project_id]">{{asset.project_name}}</a></div><button class="close-btn" (click)="selectedAsset.set(null)" aria-label="Close asset details">×</button></div>
        <section><h3>Current state</h3><div class="pill-row">@for (state of asset.states; track state) { <span class="tech-pill">{{state}}</span> }</div></section>
        <section><h3>Findings</h3>@for (finding of asset.findings; track finding.id) { <div class="detail-row"><span class="badge badge-{{finding.severity}}">{{finding.severity}}</span><span>{{finding.title}}</span></div> } @empty { <p class="muted">No normalized findings affect this asset.</p> }</section>
        <section><h3>Relationships</h3>@for (relationship of asset.relationships; track relationship.id) { <div class="relationship"><span>{{relationship.source_value}}</span><b>{{relationship.type}}</b><span>{{relationship.target_value}}</span></div> } @empty { <p class="muted">No related assets observed.</p> }</section>
        <section><h3>Evidence observations</h3>@for (observation of asset.observations; track observation.id) { <div class="detail-row"><span class="badge badge-tool">{{observation.tool}}</span><span>{{observation.state}}</span><time>{{observation.observed_at | date:'short'}}</time></div> }</section>
        <a class="btn btn-primary" [routerLink]="['/scan', asset.scan_id, 'results']">Open assessment evidence</a>
      </aside>
    }
  `,
  styles: [`
    .portfolio-stats{margin-bottom:18px}.stat-note,.source-line,.muted{font-size:11px;color:var(--text-dim)}.data-card{padding:0;overflow:hidden}.click-row{cursor:pointer}.click-row:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}.asset-name{font:600 12px var(--font-mono);color:var(--text)}.risk-count{display:inline-grid;place-items:center;min-width:26px;padding:2px 7px;border-radius:12px;background:var(--bg-elevated);font:600 11px var(--font-mono)}.risk-count.has-risk{color:var(--sev-high);background:rgba(255,140,66,.14)}.finding-list,.change-grid{display:grid;gap:12px}.finding-card{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:17px 18px;background:var(--bg-card);border:1px solid var(--border);border-left:3px solid var(--border-bright);border-radius:var(--radius-lg)}.finding-card.critical{border-left-color:var(--sev-critical)}.finding-card.high{border-left-color:var(--sev-high)}.finding-card.medium{border-left-color:var(--sev-medium)}.finding-main,.finding-actions,.change-head,.change-counts{display:flex;align-items:center;gap:12px}.finding-main h3{font-size:14px}.finding-actions{margin-left:auto}.change-grid{grid-template-columns:repeat(auto-fit,minmax(330px,1fr))}.change-card{display:flex;flex-direction:column;gap:17px}.change-head{justify-content:space-between}.change-title{font-size:15px;font-weight:700;color:var(--text)}.change-counts{flex-wrap:wrap}.delta{font:600 11px var(--font-mono);padding:4px 8px;border-radius:5px;background:var(--bg-elevated)}.added,.resolved{color:var(--accent)}.removed,.risk{color:var(--sev-high)}.changed{color:var(--cyan)}.drawer-backdrop{position:fixed;inset:0;background:rgba(2,6,14,.62);z-index:190}.asset-drawer{position:fixed;z-index:200;right:0;top:0;height:100vh;width:min(560px,94vw);overflow:auto;background:var(--bg-card);border-left:1px solid var(--border-bright);box-shadow:var(--shadow-lg);padding:28px}.drawer-head{display:flex;justify-content:space-between;gap:20px;padding-bottom:22px;border-bottom:1px solid var(--border)}.drawer-head h2{font:700 19px var(--font-mono);margin:8px 0 2px;overflow-wrap:anywhere}.close-btn{font-size:28px;color:var(--text-dim)}.asset-drawer section{padding:20px 0;border-bottom:1px solid var(--border)}.asset-drawer section h3{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--text-dim);margin-bottom:12px}.pill-row{display:flex;gap:6px;flex-wrap:wrap}.detail-row{display:flex;align-items:center;gap:9px;padding:7px 0}.detail-row time{margin-left:auto;font-size:10px;color:var(--text-faint)}.relationship{display:grid;grid-template-columns:1fr auto 1fr;gap:8px;align-items:center;padding:7px 0;font:11px var(--font-mono)}.relationship b{color:var(--cyan);font-size:9px}.eyebrow{font:700 10px var(--font-mono);text-transform:uppercase;letter-spacing:.14em;color:var(--accent);margin-bottom:3px}@media(max-width:700px){.finding-card,.finding-actions{align-items:flex-start;flex-direction:column}.finding-actions{margin-left:0}.asset-drawer{padding:20px}.relationship{grid-template-columns:1fr}.relationship b{margin:2px 0}}
  `]
})
export class PortfolioComponent implements OnInit {
  private api = inject(ApiService);
  private route = inject(ActivatedRoute);
  mode = signal<PortfolioMode>('assets');
  data = signal<PortfolioResponse | null>(null);
  loading = signal(true);
  error = signal('');
  query = signal('');
  assetType = signal('all');
  severity = signal('all');
  selectedAsset = signal<PortfolioAsset | null>(null);
  projectId = signal('');

  title = computed(() => ({assets: 'Asset inventory', findings: 'Findings', changes: 'Changes'}[this.mode()]));
  subtitle = computed(() => ({assets: 'Every currently observed application asset, correlated across tools', findings: 'Prioritized security findings across every program', changes: 'New exposure, removed assets, and resolved risk since prior assessments'}[this.mode()]));
  searchPlaceholder = computed(() => ({assets: 'Search asset or program…', findings: 'Search finding, asset, or program…', changes: 'Search program…'}[this.mode()]));
  coverage = computed(() => { const s=this.data()?.summary; return s?.projects ? Math.round(s.programs_with_inventory/s.projects*100) : 0; });
  assetTypes = computed(() => [...new Set((this.data()?.assets || []).map(asset => asset.type))].sort());
  filteredAssets = computed(() => { const q=this.query().toLowerCase(); return (this.data()?.assets || []).filter(asset => (!this.projectId()||asset.project_id===this.projectId()) && (this.assetType()==='all'||asset.type===this.assetType()) && (!q||`${asset.value} ${asset.project_name} ${asset.states.join(' ')}`.toLowerCase().includes(q))); });
  filteredFindings = computed(() => { const q=this.query().toLowerCase(); return (this.data()?.findings || []).filter(finding => (!this.projectId()||finding.project_id===this.projectId()) && (this.severity()==='all'||finding.severity===this.severity()) && (!q||`${finding.title} ${finding.asset_value} ${finding.project_name}`.toLowerCase().includes(q))).sort((a,b)=>this.rank(a)-this.rank(b)); });
  filteredChanges = computed(() => { const q=this.query().toLowerCase(); return (this.data()?.changes || []).filter(change => (!this.projectId()||change.project_id===this.projectId()) && (!q||change.project_name.toLowerCase().includes(q))); });
  visibleCount = computed(() => this.mode()==='assets' ? this.filteredAssets().length : this.mode()==='findings' ? this.filteredFindings().length : this.filteredChanges().length);

  ngOnInit(): void { this.mode.set((this.route.snapshot.data['mode'] || 'assets') as PortfolioMode); this.projectId.set(this.route.snapshot.queryParamMap.get('project') || ''); this.load(); }
  load(): void { this.loading.set(true); this.error.set(''); this.api.getPortfolio().subscribe({next:data=>{this.data.set(data);this.loading.set(false)},error:error=>{this.error.set(error?.error?.detail||'Could not load portfolio data.');this.loading.set(false)}}); }
  private rank(finding: PortfolioFinding): number { return ({critical:0,high:1,medium:2,low:3,info:4} as Record<string,number>)[finding.severity] ?? 5; }
}
