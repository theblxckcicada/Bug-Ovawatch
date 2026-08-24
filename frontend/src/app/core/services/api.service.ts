
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Project, Target, Scan, ToolResult, ToolInfo, ToolApiKeysConfig, InventorySnapshot, InventoryDelta, PortfolioResponse, SystemStatus } from '../models';
import { AuthService } from './auth.service';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private base = '/api';

  constructor(private http: HttpClient, private auth: AuthService) {}

  // ── Projects ──────────────────────────────────────────────────
  getProjects(): Observable<Project[]> {
    return this.http.get<Project[]>(`${this.base}/projects/`);
  }
  getProject(id: string): Observable<Project> {
    return this.http.get<Project>(`${this.base}/projects/${id}`);
  }
  createProject(name: string, description: string): Observable<Project> {
    return this.http.post<Project>(`${this.base}/projects/`, { name, description });
  }
  /** Patch editable project fields (name/description) after creation. */
  updateProject(id: string, changes: { name?: string; description?: string }): Observable<Project> {
    return this.http.patch<Project>(`${this.base}/projects/${id}`, changes);
  }
  deleteProject(id: string): Observable<void> {
    return this.http.delete<void>(`${this.base}/projects/${id}`);
  }
  /** Remove all scan history (incl. cancelled) for a project, keeping the project. */
  clearProjectData(id: string): Observable<{ cleared_scans: number }> {
    return this.http.post<{ cleared_scans: number }>(`${this.base}/projects/${id}/clear`, {});
  }

  // ── Targets ───────────────────────────────────────────────────
  getTargets(projectId: string): Observable<Target[]> {
    return this.http.get<Target[]>(`${this.base}/projects/${projectId}/targets`);
  }
  addTarget(projectId: string, domain: string, isOos = false): Observable<Target> {
    return this.http.post<Target>(`${this.base}/projects/${projectId}/targets`, { domain, is_oos: isOos });
  }
  deleteTarget(projectId: string, targetId: string): Observable<void> {
    return this.http.delete<void>(`${this.base}/projects/${projectId}/targets/${targetId}`);
  }

  // ── Scans ─────────────────────────────────────────────────────
  startScan(projectId: string, tools: string[], wordlist?: string, reusePrevious = false): Observable<Scan> {
    return this.http.post<Scan>(`${this.base}/scans/`, {
      project_id: projectId, tools, wordlist, reuse_previous: reusePrevious,
    });
  }
  getScans(projectId: string): Observable<Scan[]> {
    return this.http.get<Scan[]>(`${this.base}/scans/${projectId}/list`);
  }
  getScan(scanId: string): Observable<Scan> {
    return this.http.get<Scan>(`${this.base}/scans/${scanId}`);
  }
  cancelScan(scanId: string): Observable<any> {
    return this.http.post<any>(`${this.base}/scans/${scanId}/cancel`, {});
  }

  /** SSE URL carrying the bearer token as a query param (EventSource can't set headers). */
  progressStreamUrl(scanId: string): string {
    const token = this.auth.token;
    const suffix = token ? `?token=${encodeURIComponent(token)}` : '';
    return `${this.base}/scans/${scanId}/progress${suffix}`;
  }

  // ── Results ───────────────────────────────────────────────────
  getResults(scanId: string): Observable<ToolResult[]> {
    return this.http.get<ToolResult[]>(`${this.base}/results/${scanId}`);
  }
  getResultsSummary(scanId: string): Observable<any> {
    return this.http.get<any>(`${this.base}/results/${scanId}/summary`);
  }
  /** Delete filesystem artifacts while retaining assessment records in SQLite. */
  deleteRawOutputs(scanId: string): Observable<{ files_deleted: number; bytes_freed: number; database_records_retained: boolean }> {
    return this.http.delete<{ files_deleted: number; bytes_freed: number; database_records_retained: boolean }>(`${this.base}/results/${scanId}/artifacts`);
  }

  getInventory(scanId: string): Observable<InventorySnapshot> {
    return this.http.get<InventorySnapshot>(`${this.base}/inventory/${scanId}`);
  }

  getInventoryDelta(scanId: string): Observable<InventoryDelta> {
    return this.http.get<InventoryDelta>(`${this.base}/inventory/${scanId}/delta`);
  }

  getPortfolio(): Observable<PortfolioResponse> {
    return this.http.get<PortfolioResponse>(`${this.base}/portfolio`);
  }

  getSystemStatus(): Observable<SystemStatus> {
    return this.http.get<SystemStatus>(`${this.base}/portfolio/system`);
  }

  // ── Tools ─────────────────────────────────────────────────────
  getTools(): Observable<ToolInfo[]> {
    return this.http.get<ToolInfo[]>(`${this.base}/tools/`);
  }

  // ── Settings ──────────────────────────────────────────────────
  getToolApiKeys(): Observable<ToolApiKeysConfig> {
    return this.http.get<ToolApiKeysConfig>(`${this.base}/settings/api-keys`);
  }
  saveToolApiKeys(cfg: ToolApiKeysConfig): Observable<any> {
    return this.http.post<any>(`${this.base}/settings/api-keys`, cfg);
  }

  artifactUrl(scanId: string, path: string): string {
    return `${this.base}/results/${scanId}/artifact?path=${encodeURIComponent(path)}${this.tokenQuery()}`;
  }

  artifactTextUrl(scanId: string, path: string): string {
    return `${this.base}/results/${scanId}/artifact-text?path=${encodeURIComponent(path)}${this.tokenQuery()}`;
  }

  /** Token as an extra query param — artifacts load via <img>/<a>, which can't set headers. */
  private tokenQuery(): string {
    const token = this.auth.token;
    return token ? `&token=${encodeURIComponent(token)}` : '';
  }
}
