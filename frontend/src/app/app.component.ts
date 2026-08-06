import { Component, inject } from "@angular/core";
import { CommonModule } from "@angular/common";
import { RouterOutlet, RouterLink, RouterLinkActive, Router } from "@angular/router";
import { AuthService } from "./core/services/auth.service";
import { ThemeService } from "./core/services/theme.service";

@Component({
  selector: "sg-root",
  standalone: true,
  imports: [CommonModule, RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    @if (auth.authenticated()) {
      <div class="shell">
        <aside class="sidebar">
          <div class="brand">
            <img class="brand-mark" src="assets/shadow-grid-mark.png" alt="ShadowGrid" />
            <div class="brand-text">
              <span class="brand-name">Shadow<span class="brand-accent">Grid</span></span>
              <span class="brand-tag">AppSec Platform</span>
            </div>
          </div>

          <nav class="nav">
            <a class="nav-link" routerLink="/dashboard" routerLinkActive="active">
              <svg viewBox="0 0 24 24" class="nav-ico"><path d="M3 3h8v8H3zM13 3h8v5h-8zM13 10h8v11h-8zM3 13h8v8H3z"/></svg>
              <span>Dashboard</span>
            </a>
            <a class="nav-link" routerLink="/projects" routerLinkActive="active">
              <svg viewBox="0 0 24 24" class="nav-ico"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
              <span>Programs</span>
            </a>
            <a class="nav-link" routerLink="/activity" routerLinkActive="active">
              <svg viewBox="0 0 24 24" class="nav-ico"><path d="M3 12h4l3 8 4-16 3 8h4"/></svg>
              <span>Scan Activity</span>
            </a>
            <a class="nav-link" routerLink="/settings" routerLinkActive="active">
              <svg viewBox="0 0 24 24" class="nav-ico"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/></svg>
              <span>Settings</span>
            </a>
          </nav>

          <div class="side-foot">
            <button class="side-btn" (click)="theme.toggle()" [title]="theme.theme() === 'dark' ? 'Switch to light' : 'Switch to dark'">
              @if (theme.theme() === 'dark') {
                <svg viewBox="0 0 24 24" class="nav-ico"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4"/></svg>
                <span>Light mode</span>
              } @else {
                <svg viewBox="0 0 24 24" class="nav-ico"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>
                <span>Dark mode</span>
              }
            </button>
            <button class="side-btn" (click)="logout()">
              <svg viewBox="0 0 24 24" class="nav-ico"><path d="M16 17l5-5-5-5M21 12H9M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/></svg>
              <span>Sign out</span>
            </button>
          </div>
        </aside>

        <main class="main-content">
          <router-outlet />
        </main>
      </div>
    } @else {
      <main class="bare"><router-outlet /></main>
    }
  `,
  styles: [`
    .shell { display:flex; min-height:100vh; }
    .bare { min-height:100vh; display:flex; flex-direction:column; }

    .sidebar {
      position:sticky; top:0; align-self:flex-start;
      width:var(--sidebar-w); height:100vh; flex-shrink:0;
      background:var(--bg-card); border-right:1px solid var(--border);
      display:flex; flex-direction:column; padding:20px 14px; gap:8px;
    }
    .brand { display:flex; align-items:center; gap:11px; padding:6px 8px 18px; }
    .brand-mark { width:38px; height:38px; border-radius:9px; }
    .brand-text { display:flex; flex-direction:column; line-height:1.15; }
    .brand-name { font-family:var(--font-head); font-size:16px; font-weight:750; letter-spacing:-.01em; color:var(--text); }
    .brand-accent { color:var(--accent); }
    .brand-tag { font-family:var(--font-mono); font-size:9.5px; letter-spacing:.14em; text-transform:uppercase; color:var(--text-dim); margin-top:2px; }

    .nav { display:flex; flex-direction:column; gap:3px; margin-top:4px; }
    .nav-link, .side-btn {
      display:flex; align-items:center; gap:11px; padding:9px 12px; border-radius:var(--radius);
      font-family:var(--font-head); font-size:13.5px; font-weight:550; color:var(--text-dim);
      transition:all 130ms ease; text-decoration:none; width:100%; text-align:left; background:none; border:none; cursor:pointer;
    }
    .nav-link:hover, .side-btn:hover { color:var(--text); background:var(--bg-hover); }
    .nav-link.active { color:var(--accent); background:var(--accent-glow); }
    .nav-ico { width:18px; height:18px; flex-shrink:0; fill:none; stroke:currentColor; stroke-width:1.9; stroke-linecap:round; stroke-linejoin:round; }
    .nav-link.active .nav-ico { stroke:var(--accent); }

    .side-foot { margin-top:auto; display:flex; flex-direction:column; gap:3px; padding-top:12px; border-top:1px solid var(--border); }

    .main-content { flex:1; min-width:0; }

    @media (max-width:820px) {
      .shell { flex-direction:column; }
      .sidebar {
        position:sticky; top:0; z-index:100; width:100%; height:auto; flex-direction:row;
        align-items:center; padding:10px 14px; gap:6px; border-right:none; border-bottom:1px solid var(--border);
        overflow-x:auto;
      }
      .brand { padding:0 8px 0 0; }
      .brand-tag { display:none; }
      .nav { flex-direction:row; margin-top:0; }
      .nav-link span, .side-btn span { display:none; }
      .side-foot { margin-top:0; margin-left:auto; flex-direction:row; border-top:none; padding-top:0; }
    }
  `],
})
export class AppComponent {
  auth = inject(AuthService);
  theme = inject(ThemeService);
  private router = inject(Router);

  logout(): void {
    this.auth.logout();
    this.router.navigate(['/login']);
  }
}
