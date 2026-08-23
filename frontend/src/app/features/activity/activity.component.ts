import { Component, OnInit, OnDestroy, signal, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ScanActivityService, ActivityEntry } from '../../core/services/scan-activity.service';

/**
 * Cross-program scan activity board. Concurrent assessments render as discrete
 * status cards — active ones grouped and highlighted, recent ones below — so
 * scanning many domains at once stays legible instead of stacking into a wall
 * of rows. Polls while mounted to reflect completions live.
 */
@Component({
  selector: 'sg-activity',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <h1 class="page-title">Assessments</h1>
          <p class="page-sub">Live and recent security assessments across every program</p>
        </div>
        <button class="btn btn-outline btn-sm" (click)="load()">
          <span [class.spin]="loading()">⟳</span> Refresh
        </button>
      </div>

      @if (loading() && entries().length === 0) {
        <div class="empty-state"><div class="spinner-sm"></div><span>Loading activity…</span></div>
      } @else if (entries().length === 0) {
        <div class="card"><div class="empty-state">
          <div class="empty-icon">📡</div>
          <h3>No scan activity</h3>
          <p>Launch an assessment from any program to see it tracked here in real time.</p>
          <a class="btn btn-primary" routerLink="/projects">Go to programs</a>
        </div></div>
      } @else {
        @if (activeEntries().length > 0) {
          <div class="section-head">
            <span class="pulse-dot"></span>
            <span class="section-title">Running now</span>
            <span class="section-count">{{activeEntries().length}}</span>
          </div>
          <div class="scan-grid">
            @for (e of activeEntries(); track e.scan.id) {
              <div class="scan-card active">
                <div class="sc-top">
                  <span class="badge badge-{{e.scan.status}}">{{e.scan.status}}</span>
                  <span class="sc-id mono">{{e.scan.id.slice(0,8)}}</span>
                </div>
                <a class="sc-project" [routerLink]="['/projects', e.project.id]">{{e.project.name}}</a>
                <div class="sc-meta mono">{{e.scan.tools.length}} tools · started {{e.scan.started_at || e.scan.created_at | date:'HH:mm'}}</div>
                <div class="sc-actions">
                  <a class="btn btn-primary btn-sm" [routerLink]="['/scan', e.scan.id, 'progress']">Live progress</a>
                  <a class="btn btn-outline btn-sm" [routerLink]="['/scan', e.scan.id, 'results']">Results so far</a>
                </div>
              </div>
            }
          </div>
        }

        <div class="section-head" style="margin-top:26px">
          <span class="section-title">Recent</span>
          <span class="section-count">{{recentEntries().length}}</span>
        </div>
        @if (recentEntries().length === 0) {
          <div class="card"><div class="empty-state" style="padding:28px"><p>No completed assessments yet.</p></div></div>
        } @else {
          <div class="scan-grid">
            @for (e of recentEntries(); track e.scan.id) {
              <div class="scan-card">
                <div class="sc-top">
                  <span class="badge badge-{{e.scan.status}}">{{e.scan.status}}</span>
                  <span class="sc-id mono">{{e.scan.id.slice(0,8)}}</span>
                </div>
                <a class="sc-project" [routerLink]="['/projects', e.project.id]">{{e.project.name}}</a>
                <div class="sc-meta mono">{{e.scan.tools.length}} tools · {{e.scan.completed_at || e.scan.created_at | date:'MMM d, HH:mm'}}</div>
                <div class="sc-actions">
                  @if (e.scan.status === 'completed') {
                    <a class="btn btn-primary btn-sm" [routerLink]="['/scan', e.scan.id, 'results']">View results</a>
                  } @else {
                    <a class="btn btn-outline btn-sm" [routerLink]="['/projects', e.project.id]">Open program</a>
                  }
                </div>
              </div>
            }
          </div>
        }
      }
    </div>
  `,
  styles: [`
    .scan-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:14px; }
    .scan-card { background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius-lg); padding:16px 18px; display:flex; flex-direction:column; gap:9px; box-shadow:var(--shadow); transition:border-color 140ms, transform 140ms; }
    .scan-card:hover { border-color:var(--border-bright); transform:translateY(-1px); }
    .scan-card.active { border-color:rgba(251,155,63,.45); }
    .sc-top { display:flex; align-items:center; justify-content:space-between; }
    .sc-top .badge { text-transform:capitalize; }
    .sc-id { font-size:11px; color:var(--text-faint); }
    .sc-project { font-family:var(--font-head); font-size:15px; font-weight:650; color:var(--text); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .sc-project:hover { color:var(--accent); }
    .sc-meta { font-size:11.5px; color:var(--text-dim); }
    .sc-actions { display:flex; gap:8px; margin-top:4px; flex-wrap:wrap; }
    .spin { display:inline-block; animation:spin .7s linear infinite; }
  `]
})
export class ActivityComponent implements OnInit, OnDestroy {
  private activityService = inject(ScanActivityService);

  entries = signal<ActivityEntry[]>([]);
  loading = signal(true);
  private timer?: number;

  activeEntries = computed(() => this.entries().filter(e => ScanActivityService.isActive(e.scan)));
  recentEntries = computed(() => this.entries().filter(e => !ScanActivityService.isActive(e.scan)).slice(0, 24));

  ngOnInit() {
    this.load();
    this.timer = window.setInterval(() => this.load(), 6000);
  }

  ngOnDestroy() {
    if (this.timer) window.clearInterval(this.timer);
  }

  load() {
    this.loading.set(true);
    this.activityService.activity().subscribe({
      next: entries => { this.entries.set(entries); this.loading.set(false); },
      error: () => this.loading.set(false),
    });
  }
}
