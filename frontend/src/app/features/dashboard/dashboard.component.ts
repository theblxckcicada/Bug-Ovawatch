import { Component, OnInit, OnDestroy, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ScanActivityService, ActivityEntry } from '../../core/services/scan-activity.service';

/**
 * Security-posture overview. Aggregates programs and their assessments into a
 * single dashboard so the product reads as an AppSec platform rather than a
 * one-off recon tool. Polls while mounted so active assessments stay current.
 */
@Component({
  selector: 'sg-dashboard',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <h1 class="page-title">Security Posture</h1>
          <p class="page-sub">Application-security assessments across all of your programs</p>
        </div>
        <a class="btn btn-primary" routerLink="/projects">Manage programs →</a>
      </div>

      @if (loading()) {
        <div class="empty-state"><div class="spinner-sm"></div><span>Loading posture…</span></div>
      } @else {
        <div class="stat-grid">
          <div class="stat-card accent">
            <div class="stat-label">Programs</div>
            <div class="stat-value green">{{programs()}}</div>
            <div class="stat-sub">application scopes under management</div>
          </div>
          <div class="stat-card" [class.danger]="active() > 0">
            <div class="stat-label">Active assessments</div>
            <div class="stat-value" [class.orange]="active() > 0">{{active()}}</div>
            <div class="stat-sub">{{active() > 0 ? 'scanning now' : 'idle'}}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Completed</div>
            <div class="stat-value cyan">{{completed()}}</div>
            <div class="stat-sub">finished assessments</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Total assessments</div>
            <div class="stat-value">{{entries().length}}</div>
            <div class="stat-sub">across every program</div>
          </div>
        </div>

        <div class="section-head">
          <span class="section-title">Recent assessment activity</span>
          @if (active() > 0) { <span class="pulse-dot"></span> }
          <span class="section-count">{{entries().length}}</span>
          <div class="section-actions"><a class="btn btn-outline btn-sm" routerLink="/activity">View all</a></div>
        </div>

        @if (entries().length === 0) {
          <div class="card">
            <div class="empty-state">
              <div class="empty-icon">🛡️</div>
              <h3>No assessments yet</h3>
              <p>Create a program, add in-scope applications, and launch your first security assessment.</p>
              <a class="btn btn-primary" routerLink="/projects">Create a program</a>
            </div>
          </div>
        } @else {
          <div class="card" style="padding:8px 0">
            @for (e of recent(); track e.scan.id) {
              <a class="feed-row" [routerLink]="rowLink(e)">
                <span class="badge badge-{{e.scan.status}} feed-status">{{e.scan.status}}</span>
                <span class="feed-project">{{e.project.name}}</span>
                <span class="feed-meta mono">{{e.scan.tools.length}} tools</span>
                <span class="feed-meta mono">{{e.scan.created_at | date:'MMM d, HH:mm'}}</span>
                <span class="feed-go">→</span>
              </a>
            }
          </div>
        }
      }
    </div>
  `,
  styles: [`
    .feed-row { display:flex; align-items:center; gap:14px; padding:11px 20px; border-bottom:1px solid var(--border); transition:background 120ms; }
    .feed-row:last-child { border-bottom:none; }
    .feed-row:hover { background:var(--bg-hover); }
    .feed-status { text-transform:capitalize; min-width:88px; justify-content:center; }
    .feed-project { font-weight:600; color:var(--text); flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .feed-meta { font-size:11.5px; color:var(--text-dim); }
    .feed-go { color:var(--text-faint); }
    @media (max-width:640px){ .feed-meta { display:none; } }
  `]
})
export class DashboardComponent implements OnInit, OnDestroy {
  private activityService = inject(ScanActivityService);

  entries = signal<ActivityEntry[]>([]);
  loading = signal(true);
  private timer?: number;

  programs = computed(() => new Set(this.entries().map(e => e.project.id)).size);
  active = computed(() => this.entries().filter(e => ScanActivityService.isActive(e.scan)).length);
  completed = computed(() => this.entries().filter(e => e.scan.status === 'completed').length);
  recent = computed(() => this.entries().slice(0, 8));

  ngOnInit() {
    this.load();
    this.timer = window.setInterval(() => this.load(), 8000);
  }

  ngOnDestroy() {
    if (this.timer) window.clearInterval(this.timer);
  }

  private load() {
    this.activityService.activity().subscribe({
      next: entries => { this.entries.set(entries); this.loading.set(false); },
      error: () => this.loading.set(false),
    });
  }

  rowLink(e: ActivityEntry): any[] {
    if (ScanActivityService.isActive(e.scan)) return ['/scan', e.scan.id, 'progress'];
    if (e.scan.status === 'completed') return ['/scan', e.scan.id, 'results'];
    return ['/projects', e.project.id];
  }
}
