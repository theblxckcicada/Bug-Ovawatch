
import { Component, OnInit, signal, computed } from '@angular/core';
import { CommonModule, DatePipe } from '@angular/common';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/services/api.service';
import { Project, Target, Scan, ToolInfo } from '../../core/models';

const DEFAULT_TOOLS = [
  'crtsh','assetfinder','subfinder','amass','shuffledns',
  'dnsx','dns_records','zone_transfer',
  'httpx','naabu','nuclei','cve_check','subdomain_takeover','wpscan','gowitness','whatweb',
  'waybackurls','gau','katana','urlfinder',
  'whois','asnmap','google_dorks'
];

const TOOL_GROUPS: Record<string, string[]> = {
  'Subdomain Enumeration': ['crtsh','assetfinder','subfinder','amass','shuffledns'],
  'DNS':                   ['dnsx','dns_records','zone_transfer'],
  'HTTP & Ports':          ['httpx','naabu'],
  'Vulnerability':         ['nuclei','cve_check','subdomain_takeover','wpscan'],
  'Screenshots, Dorks & Tech': ['gowitness','whatweb','google_dorks'],
  'URL Discovery':         ['waybackurls','gau','katana','urlfinder'],
  'Asset Discovery':       ['whois','asnmap','shodan'],
  'AI':                    ['ai_analysis'],
};

@Component({
  selector: 'sg-project-detail',
  standalone: true,
  imports: [CommonModule, RouterLink, FormsModule],
  template: `
    <div class="page">
      <!-- Breadcrumb -->
      <div class="breadcrumb">
        <a routerLink="/projects">Projects</a>
        <span class="sep">›</span>
        <span>{{project()?.name}}</span>
      </div>

      @if (project(); as p) {
        <div class="page-header">
          <div style="flex:1;min-width:0">
            @if (!editing()) {
              <h1 class="page-title">{{p.name}}</h1>
              @if (p.description) { <p class="page-sub">{{p.description}}</p> }
            } @else {
              <div class="edit-form">
                <div class="form-group">
                  <label class="form-label">Program Name</label>
                  <input class="form-input" [(ngModel)]="editName" placeholder="Program name" />
                </div>
                <div class="form-group">
                  <label class="form-label">Description</label>
                  <textarea class="form-textarea" [(ngModel)]="editDesc" placeholder="Scope, environment, notes…"></textarea>
                </div>
                <div class="edit-actions">
                  <button class="btn btn-ghost btn-sm" (click)="cancelEdit()">Cancel</button>
                  <button class="btn btn-primary btn-sm" [disabled]="!editName.trim() || savingEdit()" (click)="saveEdit()">
                    @if (savingEdit()) { <span class="spinner-sm"></span> } Save changes
                  </button>
                </div>
              </div>
            }
          </div>
          @if (!editing()) {
            <div class="header-actions">
              <button class="btn btn-outline btn-sm" (click)="startEdit()">Edit details</button>
              <button class="btn btn-outline btn-sm" (click)="showClear.set(true)" [disabled]="scans().length === 0">Clear data</button>
              <button class="btn btn-danger btn-sm" (click)="deleteProject()">Delete</button>
            </div>
          }
        </div>

        @if (message()) { <div class="alert alert-success">{{message()}}</div> }

        <div class="project-shortcuts" aria-label="Program intelligence">
          <a class="shortcut" routerLink="/assets" [queryParams]="{project:p.id}"><span>Assets</span><b>Inventory →</b></a>
          <a class="shortcut" routerLink="/findings" [queryParams]="{project:p.id}"><span>Findings</span><b>Prioritized risk →</b></a>
          <a class="shortcut" routerLink="/changes" [queryParams]="{project:p.id}"><span>Changes</span><b>Exposure drift →</b></a>
        </div>

        <!-- Tabs -->
        <div class="tab-bar">
          <button class="tab-btn" [class.active]="tab==='targets'" (click)="tab='targets'">Scope</button>
          <button class="tab-btn" [class.active]="tab==='scan'" (click)="tab='scan'">New Assessment</button>
          <button class="tab-btn" [class.active]="tab==='history'" (click)="tab='history'">Assessments</button>
        </div>

        <!-- Targets -->
        @if (tab === 'targets') {
          <div class="targets-layout">
            <div class="card">
              <div class="section-head">
                <span class="section-title">In-Scope Targets</span>
                <span class="section-count">{{inscope().length}}</span>
              </div>
              <div class="add-target">
                <input class="form-input" [(ngModel)]="newTarget" placeholder="domain.com" (keyup.enter)="addTarget(false)" />
                <button class="btn btn-primary btn-sm" (click)="addTarget(false)">Add</button>
              </div>
              @if (inscope().length === 0) {
                <div class="empty-state" style="padding:24px"><div class="empty-icon" style="font-size:24px">⊡</div><p>No targets yet</p></div>
              } @else {
                <ul class="target-list">
                  @for (t of inscope(); track t.id) {
                    <li class="target-item">
                      <span class="target-domain">{{t.domain}}</span>
                      <span class="badge badge-alive">In-Scope</span>
                      <button class="btn btn-ghost btn-sm" (click)="removeTarget(t)">✕</button>
                    </li>
                  }
                </ul>
              }
            </div>
            <div class="card">
              <div class="section-head">
                <span class="section-title">Out-of-Scope</span>
                <span class="section-count">{{oos().length}}</span>
              </div>
              <div class="add-target">
                <input class="form-input" [(ngModel)]="newOos" placeholder="*.internal.domain.com" (keyup.enter)="addTarget(true)" />
                <button class="btn btn-outline btn-sm" (click)="addTarget(true)">Add OOS</button>
              </div>
              @if (oos().length === 0) {
                <div class="empty-state" style="padding:24px"><p>No OOS rules</p></div>
              } @else {
                <ul class="target-list">
                  @for (t of oos(); track t.id) {
                    <li class="target-item">
                      <span class="target-domain">{{t.domain}}</span>
                      <span class="badge badge-dead">OOS</span>
                      <button class="btn btn-ghost btn-sm" (click)="removeTarget(t)">✕</button>
                    </li>
                  }
                </ul>
              }
            </div>
          </div>
        }

        <!-- Launch Scan -->
        @if (tab === 'scan') {
          <div class="card" style="max-width:720px">
            <h3 style="font-family:var(--font-head);font-weight:600;margin-bottom:16px">Configure Scan</h3>

            @if (inscope().length === 0) {
              <div class="alert alert-warning">Add at least one in-scope target before launching a scan.</div>
            }

            @for (entry of toolGroupEntries; track entry[0]) {
              <div class="tool-group">
                <div class="tg-head">
                  <span class="tg-name">{{entry[0]}}</span>
                  <button class="btn btn-ghost btn-sm" (click)="toggleGroup(entry[1])">Toggle All</button>
                </div>
                <div class="tg-tools">
                  @for (t of entry[1]; track t) {
                    <label class="tool-chk" [class.unavail]="!toolAvail(t)" [title]="toolError(t)">
                      <input type="checkbox" [checked]="selectedTools.has(t)" (change)="toggleTool(t)" [disabled]="!toolAvail(t)" />
                      <span class="tool-name">{{t}}</span>
                      @if (!toolAvail(t)) { <span class="badge badge-dead" style="font-size:9px">{{unavailableLabel(t)}}</span> }
                    </label>
                    @if (t === 'ai_analysis' && !toolAvail(t)) {
                      <div class="ai-warning">Configure an AI API key in Settings to enable AI Analysis.</div>
                    }
                    @if (t === 'shodan' && !toolAvail(t)) {
                      <div class="ai-warning">Save a Shodan API key in Settings to enable Shodan enrichment.</div>
                    }
                  }
                </div>
              </div>
            }

            <div class="form-group" style="margin-top:16px">
              <label class="form-label">Custom Wordlist Path (optional)</label>
              <input class="form-input" [(ngModel)]="customWordlist" placeholder="/app/data/wordlists/custom.txt" />
            </div>

            <button class="btn btn-primary" style="margin-top:8px"
              [disabled]="inscope().length === 0 || launching()"
              (click)="launchScan()">
              @if (launching()) { <span class="spinner-sm"></span> } Launch Scan ({{selectedTools.size}} tools)
            </button>
          </div>

          <!-- Resume vs. new scan prompt -->
          @if (showResumePrompt()) {
            <div class="modal-backdrop" (click)="cancelResumePrompt()">
              <div class="modal-card" (click)="$event.stopPropagation()">
                <h3>Previous scan detected</h3>
                <p class="modal-text">
                  This project already has scan results. Continue from the previous
                  results (reuses finished tools, only runs new/missing ones), or start
                  a fresh scan from scratch?
                </p>
                <div class="modal-actions">
                  <button class="btn btn-outline btn-sm" (click)="cancelResumePrompt()">Cancel</button>
                  <button class="btn btn-outline btn-sm" (click)="confirmLaunch(false)">Start New Scan</button>
                  <button class="btn btn-primary btn-sm" (click)="confirmLaunch(true)">Continue Previous</button>
                </div>
              </div>
            </div>
          }
        }

        <!-- History -->
        @if (tab === 'history') {
          <div class="card">
            <div class="section-head">
              <span class="section-title">Assessments</span>
              <span class="section-count">{{scans().length}}</span>
              @if (scans().length > 0) {
                <div class="section-actions">
                  <button class="btn btn-outline btn-sm" (click)="showClear.set(true)">Clear all data</button>
                </div>
              }
            </div>
            @if (scans().length === 0) {
              <div class="empty-state"><div class="empty-icon">🛡️</div><p>No assessments run yet</p></div>
            } @else {
              <div class="table-wrap">
                <table>
                  <thead><tr><th>Assessment</th><th>Status</th><th>Tools</th><th>Started</th><th>Completed</th><th>Actions</th></tr></thead>
                  <tbody>
                    @for (s of scans(); track s.id) {
                      <tr>
                        <td class="td-mono" style="font-size:11px">{{s.id.slice(0,8)}}…</td>
                        <td><span class="badge badge-{{s.status}}">{{s.status}}</span></td>
                        <td>{{s.tools.length}} tools</td>
                        <td style="font-size:11px;color:var(--text-dim)">{{s.started_at | date:'short'}}</td>
                        <td style="font-size:11px;color:var(--text-dim)">{{s.completed_at | date:'short'}}</td>
                        <td>
                          <div style="display:flex;gap:6px;flex-wrap:wrap">
                            @if (s.status === 'running') {
                              <a class="btn btn-outline btn-sm" [routerLink]="['/scan', s.id, 'progress']">Live</a>
                              <a class="btn btn-primary btn-sm" [routerLink]="['/scan', s.id, 'results']">Results</a>
                            } @else if (s.status === 'completed') {
                              <a class="btn btn-primary btn-sm" [routerLink]="['/scan', s.id, 'results']">Results</a>
                            }
                          </div>
                        </td>
                      </tr>
                    }
                  </tbody>
                </table>
              </div>
            }
          </div>
        }

        <!-- Clear project data confirmation -->
        @if (showClear()) {
          <div class="modal-backdrop" (click)="showClear.set(false)">
            <div class="modal-card" (click)="$event.stopPropagation()">
              <h3>Clear program data?</h3>
              <p class="modal-text">
                This permanently deletes <strong>all {{scans().length}} assessment(s)</strong> for
                <strong>{{project()?.name}}</strong> — including cancelled ones — and their results.
                Any running assessment is stopped first. Targets and the program itself are kept.
              </p>
              <div class="modal-actions">
                <button class="btn btn-ghost btn-sm" (click)="showClear.set(false)">Cancel</button>
                <button class="btn btn-danger btn-sm" [disabled]="clearing()" (click)="clearData()">
                  @if (clearing()) { <span class="spinner-sm"></span> } Clear all data
                </button>
              </div>
            </div>
          </div>
        }
      }
    </div>
  `,
  styles: [`
    .project-shortcuts { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px; margin:14px 0 18px; }
    .shortcut { display:flex; flex-direction:column; gap:2px; padding:12px 14px; border:1px solid var(--border); border-radius:var(--radius); background:var(--bg-card); color:var(--text); }
    .shortcut:hover { border-color:var(--accent); }
    .shortcut span { font-weight:650; }
    .shortcut b { font-size:10px; color:var(--text-dim); font-weight:500; }
    @media(max-width:700px){.project-shortcuts{grid-template-columns:1fr}}
    .page { padding:32px; max-width:1200px; margin:0 auto; }
    .breadcrumb { display:flex; align-items:center; gap:8px; font-size:13px; color:var(--text-dim); margin-bottom:20px; }
    .breadcrumb a { color:var(--accent); }
    .sep { color:var(--text-faint); }
    .page-header { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; margin-bottom:24px; }
    .page-title { font-family:var(--font-head); font-size:24px; font-weight:700; }
    .page-sub { color:var(--text-dim); font-size:13px; margin-top:4px; }
    .header-actions { display:flex; gap:8px; flex-shrink:0; flex-wrap:wrap; justify-content:flex-end; }
    .edit-form { max-width:560px; }
    .edit-actions { display:flex; gap:8px; justify-content:flex-end; }
    .targets-layout { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
    @media (max-width:700px) { .targets-layout { grid-template-columns:1fr; } }
    .add-target { display:flex; gap:8px; margin-bottom:14px; }
    .add-target .form-input { flex:1; }
    .target-list { list-style:none; }
    .target-item { display:flex; align-items:center; gap:8px; padding:8px 0; border-bottom:1px solid var(--border); }
    .target-item:last-child { border-bottom:none; }
    .target-domain { font-family:var(--font-mono); font-size:12px; flex:1; }
    .tool-group { margin-bottom:18px; }
    .tg-head { display:flex; align-items:center; justify-content:space-between; margin-bottom:8px; }
    .tg-name { font-family:var(--font-head); font-size:12px; font-weight:600; color:var(--text-dim); text-transform:uppercase; letter-spacing:.06em; }
    .tg-tools { display:flex; flex-wrap:wrap; gap:8px; }
    .tool-chk { display:flex; align-items:center; gap:6px; background:var(--bg-elevated); border:1px solid var(--border); border-radius:var(--radius); padding:6px 10px; cursor:pointer; transition:border-color 150ms; }
    .tool-chk:hover { border-color:var(--accent); }
    .tool-chk.unavail { opacity:.5; cursor:not-allowed; }
    .tool-name { font-family:var(--font-mono); font-size:12px; }
    .ai-warning { flex-basis:100%; font-size:11px; color:var(--sev-medium); padding:4px 2px; }
    input[type=checkbox] { accent-color:var(--accent); cursor:pointer; }
    .modal-backdrop { position:fixed; inset:0; background:rgba(0,0,0,.6); display:flex; align-items:center; justify-content:center; z-index:200; }
    .modal-card { background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius-lg); padding:24px; max-width:460px; width:90%; }
    .modal-card h3 { font-family:var(--font-head); font-weight:600; margin-bottom:10px; }
    .modal-text { color:var(--text-dim); font-size:13px; line-height:1.5; margin-bottom:20px; }
    .modal-actions { display:flex; gap:8px; justify-content:flex-end; flex-wrap:wrap; }
  `]
})
export class ProjectDetailComponent implements OnInit {
  project = signal<Project | null>(null);
  targets = signal<Target[]>([]);
  scans = signal<Scan[]>([]);
  availableTools = signal<ToolInfo[]>([]);
  launching = signal(false);
  showResumePrompt = signal(false);
  // Edit-details + clear-data state (T4/T5 surfaced in the UI).
  editing = signal(false);
  savingEdit = signal(false);
  showClear = signal(false);
  clearing = signal(false);
  message = signal('');
  editName = '';
  editDesc = '';
  tab = 'targets';
  newTarget = '';
  newOos = '';
  customWordlist = '';
  selectedTools = new Set<string>(DEFAULT_TOOLS);

  inscope = computed(() => this.targets().filter((t: any) => !t.is_oos));
  oos     = computed(() => this.targets().filter((t: any) => t.is_oos));
  get toolGroupEntries() { return Object.entries(TOOL_GROUPS); }

  constructor(private route: ActivatedRoute, private api: ApiService, private router: Router) {}

  ngOnInit() {
    const id = this.route.snapshot.paramMap.get('id')!;
    this.api.getProject(id).subscribe(p => this.project.set(p));
    this.api.getTargets(id).subscribe(ts => this.targets.set(ts));
    this.api.getScans(id).subscribe(ss => this.scans.set(ss.sort((a,b) => b.created_at.localeCompare(a.created_at))));
    this.api.getTools().subscribe(ts => this.availableTools.set(ts));
  }

  toolAvail(name: string): boolean {
    const t = this.availableTools().find(x => x.name === name);
    return t ? t.available : true;
  }

  toolError(name: string): string {
    const t = this.availableTools().find(x => x.name === name);
    return t?.availability_error || '';
  }

  unavailableLabel(name: string): string {
    return ['ai_analysis', 'shodan'].includes(name) ? 'needs API key' : 'unavailable';
  }

  addTarget(isOos: boolean) {
    const domain = isOos ? this.newOos.trim() : this.newTarget.trim();
    if (!domain) return;
    const pid = this.project()!.id;
    this.api.addTarget(pid, domain, isOos).subscribe(t => {
      this.targets.update(ts => [...ts, t]);
      if (isOos) this.newOos = ''; else this.newTarget = '';
    });
  }

  removeTarget(t: Target) {
    this.api.deleteTarget(this.project()!.id, t.id).subscribe(() =>
      this.targets.update(ts => ts.filter(x => x.id !== t.id)));
  }

  toggleTool(name: string) {
    if (!this.toolAvail(name)) return;
    if (this.selectedTools.has(name)) this.selectedTools.delete(name);
    else this.selectedTools.add(name);
  }

  toggleGroup(tools: string[]) {
    const available = tools.filter(t => this.toolAvail(t));
    const allOn = available.every(t => this.selectedTools.has(t));
    available.forEach(t => allOn ? this.selectedTools.delete(t) : this.selectedTools.add(t));
  }

  /** A finished prior scan means we can offer to resume from its results. */
  private hasPriorScan(): boolean {
    return this.scans().some(s => ['completed', 'cancelled', 'failed'].includes(s.status));
  }

  launchScan() {
    if (this.inscope().length === 0 || this.launching()) return;
    // If the project already has results, ask whether to resume or start fresh.
    if (this.hasPriorScan()) {
      this.showResumePrompt.set(true);
      return;
    }
    this.startScan(false);
  }

  confirmLaunch(reusePrevious: boolean) {
    this.showResumePrompt.set(false);
    this.startScan(reusePrevious);
  }

  cancelResumePrompt() {
    this.showResumePrompt.set(false);
  }

  private startScan(reusePrevious: boolean) {
    if (this.inscope().length === 0) return;
    this.launching.set(true);
    this.api.startScan(this.project()!.id, [...this.selectedTools], this.customWordlist || undefined, reusePrevious)
      .subscribe({
        next: scan => this.router.navigate(['/scan', scan.id, 'progress']),
        error: () => this.launching.set(false),
      });
  }

  // ── Edit details (T4) ───────────────────────────────────────────
  startEdit() {
    const p = this.project();
    if (!p) return;
    this.editName = p.name;
    this.editDesc = p.description || '';
    this.message.set('');
    this.editing.set(true);
  }

  cancelEdit() {
    this.editing.set(false);
  }

  saveEdit() {
    const p = this.project();
    if (!p || !this.editName.trim() || this.savingEdit()) return;
    this.savingEdit.set(true);
    this.api.updateProject(p.id, { name: this.editName.trim(), description: this.editDesc.trim() })
      .subscribe({
        next: updated => {
          this.project.set(updated);
          this.savingEdit.set(false);
          this.editing.set(false);
          this.flash('Program details updated.');
        },
        error: () => this.savingEdit.set(false),
      });
  }

  // ── Clear all program data (T5) ─────────────────────────────────
  clearData() {
    const p = this.project();
    if (!p || this.clearing()) return;
    this.clearing.set(true);
    this.api.clearProjectData(p.id).subscribe({
      next: res => {
        this.clearing.set(false);
        this.showClear.set(false);
        this.scans.set([]);
        this.project.update(cur => cur ? { ...cur, scan_count: 0 } : cur);
        this.flash(`Cleared ${res.cleared_scans} assessment(s) and their data.`);
      },
      error: () => this.clearing.set(false),
    });
  }

  private flash(msg: string) {
    this.message.set(msg);
    setTimeout(() => this.message.set(''), 4000);
  }

  deleteProject() {
    if (!confirm('Delete this program and all its data?')) return;
    this.api.deleteProject(this.project()!.id).subscribe(() => this.router.navigate(['/projects']));
  }
}
