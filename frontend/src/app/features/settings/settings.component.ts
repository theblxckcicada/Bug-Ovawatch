import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/services/api.service';
import { SystemStatus, ToolApiKeysConfig } from '../../core/models';

@Component({
  selector: 'sg-settings',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="page">
      <h1 class="page-title">Settings</h1>
      <p class="page-sub" style="margin-bottom:28px">Configure recon provider keys and AI analysis keys</p>

      <div class="settings-grid">
        <div class="card">
          <h3 class="section-title">Recon API Keys</h3>
          <p class="section-copy">Optional keys used by recon tools that need authenticated APIs. Blank fields keep the existing saved value.</p>

          <div class="form-group">
            <label class="form-label">ProjectDiscovery Cloud API Key</label>
            <input class="form-input" type="password" [(ngModel)]="apiKeys.pdcp_api_key" placeholder="Needed for asnmap / PDCP-backed features" />
            <span class="hint">Stored as <span class="mono">PDCP_API_KEY</span> at runtime.</span>
          </div>

          <div class="form-group">
            <label class="form-label">GitHub Token</label>
            <input class="form-input" type="password" [(ngModel)]="apiKeys.github_token" placeholder="Optional for providers that query GitHub" />
          </div>

          <div class="form-group">
            <label class="form-label">Shodan API Key</label>
            <input class="form-input" type="password" [(ngModel)]="apiKeys.shodan_api_key" placeholder="Enables selectable Shodan enrichment" />
            <span class="hint">The Shodan tool runs only when selected for an assessment. Filtered searches may consume Shodan query credits.</span>
          </div>

          <div class="two-col">
            <div class="form-group">
              <label class="form-label">Censys API ID</label>
              <input class="form-input" type="password" [(ngModel)]="apiKeys.censys_api_id" placeholder="Optional" />
            </div>
            <div class="form-group">
              <label class="form-label">Censys API Secret</label>
              <input class="form-input" type="password" [(ngModel)]="apiKeys.censys_api_secret" placeholder="Optional" />
            </div>
          </div>

          <div class="form-group">
            <label class="form-label">Chaos API Key</label>
            <input class="form-input" type="password" [(ngModel)]="apiKeys.chaos_key" placeholder="Optional ProjectDiscovery Chaos key" />
          </div>

          <div class="form-group">
            <label class="form-label">WPScan API Token</label>
            <input class="form-input" type="password" [(ngModel)]="apiKeys.wpscan_api_token" placeholder="Optional — enables the WordPress Vulnerability Database" />
            <span class="hint">Stored as <span class="mono">WPSCAN_API_TOKEN</span>. Without it wpscan still runs with built-in checks only.</span>
          </div>

          <div class="form-group">
            <label class="form-label">SerpApi API Key</label>
            <input class="form-input" type="password" [(ngModel)]="apiKeys.serpapi_api_key" placeholder="Enables Google dorking through SerpApi" />
            <span class="hint">Stored as <span class="mono">SERPAPI_API_KEY</span>. Without it, dorking falls back to DuckDuckGo.</span>
          </div>

          <div class="form-group">
            <label class="form-label">Hunter API Key</label>
            <input class="form-input" type="password" [(ngModel)]="apiKeys.hunter_api_key" placeholder="Enables domain email discovery and optional verification" />
            <span class="hint">Stored as <span class="mono">HUNTER_API_KEY</span>. Email verification is opt-in per assessment and may consume additional Hunter credits.</span>
          </div>
        </div>

        <div class="card ai-card">
          <h3 class="section-title">AI Analysis API Keys</h3>
          <p class="section-copy">Required only for the AI Analysis scan option. Add at least one provider key to enable the tool.</p>

          <div class="form-group">
            <label class="form-label">ChatGPT / OpenAI API Key</label>
            <input class="form-input" type="password" [(ngModel)]="apiKeys.openai_api_key" placeholder="sk-…" />
          </div>

          <div class="form-group">
            <label class="form-label">Claude / Anthropic API Key</label>
            <input class="form-input" type="password" [(ngModel)]="apiKeys.anthropic_api_key" placeholder="sk-ant-…" />
          </div>

          <div class="form-group">
            <label class="form-label">Google AI / Gemini API Key</label>
            <input class="form-input" type="password" [(ngModel)]="apiKeys.google_ai_api_key" placeholder="Optional" />
          </div>

          <div class="two-col">
            <div class="form-group">
              <label class="form-label">DeepSeek API Key</label>
              <input class="form-input" type="password" [(ngModel)]="apiKeys.deepseek_api_key" placeholder="Optional" />
            </div>
            <div class="form-group">
              <label class="form-label">Groq API Key</label>
              <input class="form-input" type="password" [(ngModel)]="apiKeys.groq_api_key" placeholder="Optional" />
            </div>
          </div>

          <div class="alert alert-warning" style="margin-bottom:16px">AI Analysis stays disabled in tool selection until one AI key is saved.</div>
        </div>
      </div>

      <div class="card" style="max-width:960px;margin-top:16px">
        <h3 class="section-title" style="margin-bottom:16px">Save API Keys</h3>
        @if (keysSaved()) {
          <div class="alert alert-success" style="margin-bottom:16px">✓ API keys saved</div>
        }
        @if (keysError()) {
          <div class="alert alert-danger" style="margin-bottom:16px">✗ {{keysError()}}</div>
        }
        <button class="btn btn-primary" (click)="saveApiKeys()" [disabled]="keysSaving()">
          @if (keysSaving()) { <span class="spinner-sm"></span> }
          Save Recon + AI API Keys
        </button>
      </div>

      <div class="card" style="max-width:960px;margin-top:16px">
        <h3 class="section-title">Users and roles</h3>
        <p class="section-copy">Administrators manage users, analysts can operate assessments, and viewers have read-only access.</p>
        <div class="user-grid"><input class="form-input" [(ngModel)]="newUsername" placeholder="Username" /><input class="form-input" type="password" [(ngModel)]="newUserPassword" placeholder="Password" /><select class="form-input" [(ngModel)]="newUserRole"><option value="analyst">Analyst</option><option value="viewer">Viewer</option><option value="administrator">Administrator</option></select><button class="btn btn-outline btn-sm" (click)="addUser()">Add user</button></div>
        @for (user of users(); track user.username) { <div class="about-row"><span>{{user.username}} · {{user.role}}</span>@if (user.username !== 'admin') { <button class="btn btn-ghost btn-sm" (click)="removeUser(user.username)">Remove</button> }</div> }
      </div>

      <div class="card" style="max-width:960px;margin-top:16px">
        <h3 class="section-title">Change notifications</h3>
        <p class="section-copy">Send deduplicated assessment delta summaries to a Slack, Discord, or generic webhook.</p>
        <div class="two-col"><input class="form-input" [(ngModel)]="webhookName" placeholder="Channel name" /><input class="form-input" [(ngModel)]="webhookUrl" placeholder="https://…" /></div>
        <button class="btn btn-outline btn-sm" style="margin-top:10px" (click)="addWebhook()">Add webhook</button>
        @for (channel of notifications(); track channel.id) { <div class="about-row"><span>{{channel.name}}</span><button class="btn btn-ghost btn-sm" (click)="removeWebhook(channel.id)">Remove</button></div> }
      </div>

      <div class="card" style="max-width:960px;margin-top:16px">
        <h3 class="section-title">System Health</h3>
        <p class="section-copy">Local database, storage capacity, and scanner readiness.</p>
        @if (system(); as status) {
          <div class="health-grid">
            <div class="health-item"><span>Database</span><b class="mono">SQLite · {{formatBytes(status.database_size)}}</b></div>
            <div class="health-item"><span>Free evidence storage</span><b>{{formatBytes(status.output_free)}}</b></div>
            <div class="health-item"><span>Scanner coverage</span><b>{{status.tools_available}} / {{status.tools_total}}</b></div>
          </div>
          @if (missingTools().length) {
            <details><summary>{{missingTools().length}} unavailable scanners</summary><div class="tool-health">@for (tool of missingTools(); track tool.name) { <div><span class="badge badge-error">{{tool.name}}</span><span>{{tool.reason}}</span></div> }</div></details>
          }
        } @else { <div class="empty-state" style="padding:20px"><div class="spinner-sm"></div><span>Checking system health…</span></div> }
      </div>

      <div class="card" style="max-width:960px;margin-top:16px">
        <h3 class="section-title" style="margin-bottom:16px">About</h3>
        <div class="about-row"><span>Version</span><span class="mono">3.0.0</span></div>
        <div class="about-row"><span>Primary Storage</span><span class="mono">SQLite (mandatory)</span></div>
        <div class="about-row"><span>Database</span><span class="mono">/app/output/shadowgrid.db</span></div>
        <div class="about-row"><span>Output Directory</span><span class="mono">/app/output</span></div>
        <div class="about-row"><span>Data Directory</span><span class="mono">/app/data</span></div>
      </div>
    </div>
  `,
  styles: [`
    .page { padding:32px; max-width:1200px; margin:0 auto; }
    .page-title { font-family:var(--font-head); font-size:24px; font-weight:700; }
    .settings-grid { display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:16px; align-items:start; }
    .ai-card { grid-column:1 / -1; max-width:720px; }
    .section-title { font-family:var(--font-head); font-weight:600; margin-bottom:4px; }
    .section-copy { font-size:12px; color:var(--text-dim); margin-bottom:20px; }
    .toggle-row { display:flex; align-items:center; justify-content:space-between; cursor:pointer; }
    input[type=checkbox] { width:18px; height:18px; accent-color:var(--accent); }
    .separator { font-size:11px; color:var(--text-faint); margin:-12px 0 16px; text-align:center; }
    .hint { font-size:11px; color:var(--text-dim); }
    .two-col { display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:12px; }
    .about-row { display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid var(--border); font-size:13px; }
    .about-row:last-child { border-bottom:none; }
    .health-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px; margin-bottom:14px; }
    .health-item { padding:12px; border-radius:var(--radius); background:var(--bg-elevated); display:flex; flex-direction:column; gap:3px; }
    .health-item span { font-size:11px; color:var(--text-dim); }
    details summary { cursor:pointer; color:var(--text-dim); font-size:12px; }
    .tool-health { display:grid; gap:7px; margin-top:10px; }
    .tool-health div { display:flex; align-items:center; gap:8px; font-size:11px; color:var(--text-dim); }
    .user-grid { display:grid;grid-template-columns:1fr 1fr 150px auto;gap:8px;margin-bottom:12px; }
    @media (max-width: 900px) { .settings-grid, .two-col { grid-template-columns:1fr; } .ai-card { max-width:none; } }
  `]
})
export class SettingsComponent implements OnInit {
  system = signal<SystemStatus | null>(null);
  apiKeys: ToolApiKeysConfig = {
    pdcp_api_key:'', github_token:'', shodan_api_key:'', censys_api_id:'', censys_api_secret:'', chaos_key:'',
    wpscan_api_token:'', serpapi_api_key:'', hunter_api_key:'',
    openai_api_key:'', anthropic_api_key:'', google_ai_api_key:'', deepseek_api_key:'', groq_api_key:''
  };

  keysSaving = signal(false);
  keysSaved = signal(false);
  keysError = signal('');
  notifications = signal<any[]>([]);
  webhookName = '';
  webhookUrl = '';
  users = signal<any[]>([]);
  newUsername = '';
  newUserPassword = '';
  newUserRole = 'analyst';

  constructor(private api: ApiService) {}

  ngOnInit() {
    this.api.getToolApiKeys().subscribe(c => { this.apiKeys = { ...this.apiKeys, ...c }; });
    this.api.getSystemStatus().subscribe({ next: status => this.system.set(status), error: () => {} });
    this.api.getNotifications().subscribe(rows => this.notifications.set(rows));
    this.api.getUsers().subscribe({next: rows => this.users.set(rows), error: () => {}});
  }

  missingTools() { return this.system()?.tools.filter(tool => !tool.available) || []; }
  formatBytes(value: number): string { const units=['B','KB','MB','GB','TB']; let size=value,index=0; while(size>=1024&&index<units.length-1){size/=1024;index++;} return `${size.toFixed(index ? 1 : 0)} ${units[index]}`; }

  saveApiKeys() {
    this.keysSaving.set(true); this.keysSaved.set(false); this.keysError.set('');
    this.api.saveToolApiKeys(this.apiKeys).subscribe({
      next: () => { this.keysSaving.set(false); this.keysSaved.set(true); this.api.getToolApiKeys().subscribe(c => this.apiKeys = { ...this.apiKeys, ...c }); setTimeout(() => this.keysSaved.set(false), 3000); },
      error: e => { this.keysSaving.set(false); this.keysError.set(e.message || 'Save failed'); },
    });
  }

  addWebhook() {
    if (!this.webhookName.trim() || !this.webhookUrl.trim()) return;
    this.api.createNotification(this.webhookName.trim(), this.webhookUrl.trim()).subscribe(channel => {
      this.notifications.update(rows => [...rows, channel]); this.webhookName=''; this.webhookUrl='';
    });
  }

  removeWebhook(id: string) {
    this.api.deleteNotification(id).subscribe(() =>
      this.notifications.update(rows => rows.filter(channel => channel.id !== id)));
  }

  addUser() {
    if (!this.newUsername.trim() || this.newUserPassword.length < 8) return;
    this.api.createUser(this.newUsername.trim(), this.newUserPassword, this.newUserRole).subscribe(user => {
      this.users.update(rows => [...rows, user]); this.newUsername=''; this.newUserPassword='';
    });
  }

  removeUser(username: string) {
    this.api.deleteUser(username).subscribe(() =>
      this.users.update(rows => rows.filter(user => user.username !== username)));
  }
}
