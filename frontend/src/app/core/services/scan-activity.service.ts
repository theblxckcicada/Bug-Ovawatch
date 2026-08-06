import { Injectable, inject } from '@angular/core';
import { Observable, forkJoin, of } from 'rxjs';
import { map, switchMap } from 'rxjs/operators';
import { ApiService } from './api.service';
import { Project, Scan } from '../models';

/** A scan paired with the program it belongs to, for cross-project views. */
export interface ActivityEntry {
  project: Project;
  scan: Scan;
}

const RUNNING = new Set(['running', 'pending']);

/**
 * Aggregates scans across every program into a single, chronologically-ordered
 * activity feed. This powers the dashboard posture tiles and the Scan Activity
 * page, replacing the old per-domain stacking with one cohesive view.
 */
@Injectable({ providedIn: 'root' })
export class ScanActivityService {
  private api = inject(ApiService);

  /** All scans across all programs, newest first, each tagged with its program. */
  activity(): Observable<ActivityEntry[]> {
    return this.api.getProjects().pipe(
      switchMap((projects: Project[]) => {
        if (projects.length === 0) {
          return of([] as ActivityEntry[]);
        }
        return forkJoin(
          projects.map(project =>
            this.api.getScans(project.id).pipe(
              map(scans => scans.map(scan => ({ project, scan })))
            )
          )
        ).pipe(
          map(perProject => perProject
            .flat()
            .sort((a, b) => b.scan.created_at.localeCompare(a.scan.created_at))
          )
        );
      })
    );
  }

  static isActive(scan: Scan): boolean {
    return RUNNING.has(scan.status);
  }
}
