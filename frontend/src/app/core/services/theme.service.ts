import { Injectable, signal } from '@angular/core';

type Theme = 'light' | 'dark';
const THEME_KEY = 'sg_theme';

/**
 * Light/dark theme controller.
 *
 * The chosen theme is persisted and reflected as a `data-theme` attribute on the
 * document root, which the global stylesheet uses to override the OS preference.
 * When the user has never chosen, we follow `prefers-color-scheme`.
 */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  /** Reactive current theme so the UI (e.g. the toggle icon) can react to changes. */
  readonly theme = signal<Theme>(this.initial());

  constructor() {
    this.apply(this.theme());
  }

  toggle(): void {
    this.set(this.theme() === 'dark' ? 'light' : 'dark');
  }

  set(theme: Theme): void {
    this.theme.set(theme);
    localStorage.setItem(THEME_KEY, theme);
    this.apply(theme);
  }

  private initial(): Theme {
    const stored = localStorage.getItem(THEME_KEY);
    if (stored === 'light' || stored === 'dark') {
      return stored;
    }
    const prefersLight =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-color-scheme: light)').matches;
    return prefersLight ? 'light' : 'dark';
  }

  private apply(theme: Theme): void {
    document.documentElement.setAttribute('data-theme', theme);
  }
}
