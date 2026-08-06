import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/services/api.service';
import { StorageConfig, ToolApiKeysConfig } from '../../core/models';

@Component({
  selector: 'sg-settings',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="page">
      <h1 class="page-title">Settings</h1>
      <p class="page-sub" style="margin-bottom:28px">Configure storage, recon provider keys, and AI analysis keys</p>

      <div class="settings-grid">
        <div class="card">
          <h3 class="section-title">Azure Table Storage</h3>
          <p class="section-copy">Optional — results are always saved to disk. Enable Azure for additional cloud backup and multi-instance sync.</p>

          <label class="toggle-row" style="margin-bottom:20px">
            <span>Enable Azure Table Storage</span>
            <input type="checkbox" [(ngModel)]="storageCfg.azure_enabled" />
          </label>

          @if (storageCfg.azure_enabled) {
            <div class="form-group">
              <label class="form-label">Connection String (preferred)</label>
              <input class="form-input" [(ngModel)]="storageCfg.connection_string" placeholder="DefaultEndpointsProtocol=https;AccountName=…" />
            </div>
            <p class="separator">— OR use account name + key —</p>
            <div class="form-group">
              <label class="form-label">Account Name</label>
              <input class="form-input" [(ngModel)]="storageCfg.account_name" placeholder="mystorageaccount" />
            </div>
            <div class="form-group">
              <label class="form-label">Account Key</label>
              <input class="form-input" type="password" [(ngModel)]="storageCfg.account_key" placeholder="Leave blank to keep existing key" />
            </div>
            <div class="form-group">
              <label class="form-label">Table Prefix</label>
              <input class="form-input" [(ngModel)]="storageCfg.table_prefix" placeholder="shadowgrid" />
              <span class="hint">Tables: {{storageCfg.table_prefix}}Projects, {{storageCfg.table_prefix}}Targets, {{storageCfg.table_prefix}}Scans, {{storageCfg.table_prefix}}Results</span>
            </div>
          }

          @if (storageSaved()) {
            <div class="alert alert-success" style="margin-bottom:16px">✓ Storage configuration saved</div>
          }
          @if (storageError()) {
            <div class="alert alert-danger" style="margin-bottom:16px">✗ {{storageError()}}</div>
          }

          <button class="btn btn-primary" (click)="saveStorage()" [disabled]="storageSaving()">
            @if (storageSaving()) { <span class="spinner-sm"></span> }
            Save Storage
          </button>
        </div>

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
            <input class="form-input" type="password" [(ngModel)]="apiKeys.shodan_api_key" placeholder="Optional future provider key" />
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

          <div class="two-col">
            <div class="form-group">
              <label class="form-label">Google Search (CSE) API Key</label>
              <input class="form-input" type="password" [(ngModel)]="apiKeys.google_cse_api_key" placeholder="Enables live Google dorking results" />
            </div>
            <div class="form-group">
              <label class="form-label">Google Search Engine ID (cx)</label>
              <input class="form-input" [(ngModel)]="apiKeys.google_cse_cx" placeholder="Programmable Search Engine ID" />
            </div>
          </div>
          <span class="hint">Without these, dorking falls back to DuckDuckGo for live results.</span>
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
        <h3 class="section-title" style="margin-bottom:16px">About</h3>
        <div class="about-row"><span>Version</span><span class="mono">3.0.0</span></div>
        <div class="about-row"><span>Storage</span><span class="mono">File (always) + Azure (optional)</span></div>
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
    @media (max-width: 900px) { .settings-grid, .two-col { grid-template-columns:1fr; } .ai-card { max-width:none; } }
  `]
})
export class SettingsComponent implements OnInit {
  storageCfg: StorageConfig = { azure_enabled:false, connection_string:'', account_name:'', account_key:'', table_prefix:'shadowgrid' };
  apiKeys: ToolApiKeysConfig = {
    pdcp_api_key:'', github_token:'', shodan_api_key:'', censys_api_id:'', censys_api_secret:'', chaos_key:'',
    wpscan_api_token:'', google_cse_api_key:'', google_cse_cx:'',
    openai_api_key:'', anthropic_api_key:'', google_ai_api_key:'', deepseek_api_key:'', groq_api_key:''
  };

  storageSaving = signal(false);
  storageSaved = signal(false);
  storageError = signal('');
  keysSaving = signal(false);
  keysSaved = signal(false);
  keysError = signal('');

  constructor(private api: ApiService) {}

  ngOnInit() {
    this.api.getStorageConfig().subscribe(c => { this.storageCfg = { ...c, account_key: '' }; });
    this.api.getToolApiKeys().subscribe(c => { this.apiKeys = { ...this.apiKeys, ...c }; });
  }

  saveStorage() {
    this.storageSaving.set(true); this.storageSaved.set(false); this.storageError.set('');
    this.api.saveStorageConfig(this.storageCfg).subscribe({
      next: () => { this.storageSaving.set(false); this.storageSaved.set(true); setTimeout(() => this.storageSaved.set(false), 3000); },
      error: e => { this.storageSaving.set(false); this.storageError.set(e.message || 'Save failed'); },
    });
  }

  saveApiKeys() {
    this.keysSaving.set(true); this.keysSaved.set(false); this.keysError.set('');
    this.api.saveToolApiKeys(this.apiKeys).subscribe({
      next: () => { this.keysSaving.set(false); this.keysSaved.set(true); this.api.getToolApiKeys().subscribe(c => this.apiKeys = { ...this.apiKeys, ...c }); setTimeout(() => this.keysSaved.set(false), 3000); },
      error: e => { this.keysSaving.set(false); this.keysError.set(e.message || 'Save failed'); },
    });
  }
}
