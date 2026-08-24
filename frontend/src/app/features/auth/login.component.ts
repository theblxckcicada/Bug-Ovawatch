import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { AuthService } from '../../core/services/auth.service';

/**
 * Combined first-run setup / login screen.
 * The route supplies a `mode` ('setup' | 'login'); the component re-checks the
 * backend status on init so a stale link cannot show the wrong form.
 */
@Component({
  selector: 'sg-login',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="auth-wrap">
      <div class="auth-card">
        <div class="auth-logo">
          <img src="assets/shadow-grid-mark.png" alt="ShadowGrid" />
          <div class="auth-brand">
            <span>Shadow<span class="accent">Grid</span></span>
            <small>Application Security Platform</small>
          </div>
        </div>

        @if (mode() === 'setup') {
          <h1>Create a password</h1>
          <p class="sub">First run — set a password to protect this instance.</p>
        } @else {
          <h1>Welcome back</h1>
          <p class="sub">Sign in to your AppSec workspace.</p>
        }

        @if (mode() === 'login') {
          <div class="form-group"><label class="form-label">Username</label><input class="form-input" [(ngModel)]="username" autocomplete="username" /></div>
        }
        <div class="form-group">
          <label class="form-label">Password</label>
          <input class="form-input" type="password" autocomplete="current-password"
            [(ngModel)]="password" (keyup.enter)="submit()" placeholder="••••••••" />
        </div>

        @if (mode() === 'setup') {
          <div class="form-group">
            <label class="form-label">Confirm password</label>
            <input class="form-input" type="password" autocomplete="new-password"
              [(ngModel)]="confirm" (keyup.enter)="submit()" placeholder="••••••••" />
          </div>
        }

        @if (error()) { <div class="alert alert-danger">{{error()}}</div> }

        <button class="btn btn-primary auth-btn" [disabled]="busy()" (click)="submit()">
          @if (busy()) { <span class="spinner-sm"></span> }
          {{ mode() === 'setup' ? 'Set Password & Continue' : 'Sign In' }}
        </button>
      </div>
    </div>
  `,
  styles: [`
    .auth-wrap { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }
    .auth-card { width:100%; max-width:380px; background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius-lg); padding:32px; }
    .auth-logo { display:flex; align-items:center; gap:12px; font-family:var(--font-head); font-weight:750; margin-bottom:24px; }
    .auth-logo img { width:44px; height:44px; border-radius:10px; }
    .auth-brand { display:flex; flex-direction:column; line-height:1.2; }
    .auth-brand span { font-size:20px; letter-spacing:-.01em; }
    .auth-brand small { font-family:var(--font-mono); font-size:9.5px; font-weight:500; letter-spacing:.14em; text-transform:uppercase; color:var(--text-dim); margin-top:3px; }
    .auth-logo .accent { color:var(--accent); }
    h1 { font-family:var(--font-head); font-size:20px; font-weight:700; margin-bottom:4px; }
    .sub { color:var(--text-dim); font-size:13px; margin-bottom:20px; }
    .auth-btn { width:100%; margin-top:8px; justify-content:center; }
  `]
})
export class LoginComponent implements OnInit {
  mode = signal<'login' | 'setup'>('login');
  password = '';
  username = 'admin';
  confirm = '';
  busy = signal(false);
  error = signal('');

  constructor(private auth: AuthService, private route: ActivatedRoute, private router: Router) {}

  ngOnInit() {
    this.mode.set(this.route.snapshot.data['mode'] === 'setup' ? 'setup' : 'login');
    // Reconcile against the real backend state.
    this.auth.status().subscribe({
      next: s => {
        if (s.initialized && this.mode() === 'setup') this.router.navigate(['/login']);
        if (!s.initialized && this.mode() === 'login') this.router.navigate(['/setup']);
      },
      error: () => {},
    });
  }

  submit() {
    this.error.set('');
    if (!this.password) { this.error.set('Password is required.'); return; }

    if (this.mode() === 'setup') {
      if (this.password.length < 8) { this.error.set('Password must be at least 8 characters.'); return; }
      if (this.password !== this.confirm) { this.error.set('Passwords do not match.'); return; }
    }

    this.busy.set(true);
    const op = this.mode() === 'setup'
      ? this.auth.setup(this.password)
      : this.auth.login(this.password, this.username.trim() || 'admin');

    op.subscribe({
      next: () => this.router.navigate(['/projects']),
      error: err => {
        this.busy.set(false);
        this.error.set(err?.error?.detail || 'Authentication failed.');
      },
    });
  }
}
