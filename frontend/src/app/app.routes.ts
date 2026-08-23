
import { Routes } from '@angular/router';
import { authGuard } from './core/guards/auth.guard';

export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  {
    path: 'setup',
    data: { mode: 'setup' },
    loadComponent: () => import('./features/auth/login.component').then(m => m.LoginComponent),
  },
  {
    path: 'login',
    data: { mode: 'login' },
    loadComponent: () => import('./features/auth/login.component').then(m => m.LoginComponent),
  },
  {
    path: 'dashboard',
    canActivate: [authGuard],
    loadComponent: () => import('./features/dashboard/dashboard.component').then(m => m.DashboardComponent),
  },
  {
    path: 'activity',
    canActivate: [authGuard],
    loadComponent: () => import('./features/activity/activity.component').then(m => m.ActivityComponent),
  },
  {
    path: 'assets',
    canActivate: [authGuard],
    data: { mode: 'assets' },
    loadComponent: () => import('./features/portfolio/portfolio.component').then(m => m.PortfolioComponent),
  },
  {
    path: 'findings',
    canActivate: [authGuard],
    data: { mode: 'findings' },
    loadComponent: () => import('./features/portfolio/portfolio.component').then(m => m.PortfolioComponent),
  },
  {
    path: 'changes',
    canActivate: [authGuard],
    data: { mode: 'changes' },
    loadComponent: () => import('./features/portfolio/portfolio.component').then(m => m.PortfolioComponent),
  },
  {
    path: 'projects',
    canActivate: [authGuard],
    loadComponent: () => import('./features/projects/projects.component').then(m => m.ProjectsComponent),
  },
  {
    path: 'projects/:id',
    canActivate: [authGuard],
    loadComponent: () => import('./features/projects/project-detail.component').then(m => m.ProjectDetailComponent),
  },
  {
    path: 'scan/:id/progress',
    canActivate: [authGuard],
    loadComponent: () => import('./features/scan/scan-progress.component').then(m => m.ScanProgressComponent),
  },
  {
    path: 'scan/:scanId/results',
    canActivate: [authGuard],
    loadComponent: () => import('./features/results/results.component').then(m => m.ResultsComponent),
  },
  {
    path: 'settings',
    canActivate: [authGuard],
    loadComponent: () => import('./features/settings/settings.component').then(m => m.SettingsComponent),
  },
  { path: '**', redirectTo: 'dashboard' }
];
