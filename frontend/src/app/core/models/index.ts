
export interface Project {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
  scan_count: number;
}

export interface Target {
  id: string;
  project_id: string;
  domain: string;
  is_oos: boolean;
  added_at: string;
}

export interface Scan {
  id: string;
  project_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  tools: string[];
  wordlist: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error: string;
  scope_hash: string;
  workspace: string;
}

export interface ToolInfo {
  name: string;
  category: string;
  description: string;
  parallel_group: string;
  requires_root: boolean;
  binary_name?: string;
  binary?: string;
  available: boolean;
  availability_error?: string;
}

export interface ToolResult {
  id: string;
  scan_id: string;
  project_id: string;
  tool: string;
  category: string;
  domain: string;
  data: any[];
  count: number;
  elapsed_s: number;
  created_at: string;
  error: string;
}

export type AssetType = 'domain' | 'hostname' | 'ip_address' | 'url' | 'service' | 'technology';

export interface InventoryAsset {
  id: string;
  type: AssetType;
  value: string;
  states: string[];
  sources: string[];
  attributes: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
}

export interface AssetObservation {
  id: string;
  asset_id: string;
  tool: string;
  state: string;
  evidence_hash: string;
  observed_at: string;
}

export interface AssetRelationship {
  id: string;
  source_asset_id: string;
  target_asset_id: string;
  type: string;
  sources: string[];
}

export interface InventoryFinding {
  id: string;
  asset_id: string;
  tool: string;
  title: string;
  severity: string;
  evidence_hash: string;
  data: Record<string, unknown>;
}

export interface InventorySnapshot {
  scan_id: string;
  project_id: string;
  created_at: string;
  assets: InventoryAsset[];
  observations: AssetObservation[];
  relationships: AssetRelationship[];
  findings: InventoryFinding[];
}

export interface InventoryDelta {
  scan_id: string;
  previous_scan_id: string | null;
  added_assets: InventoryAsset[];
  removed_assets: InventoryAsset[];
  changed_assets: Array<{ asset: InventoryAsset; before: Record<string, unknown> }>;
  new_findings: InventoryFinding[];
  resolved_findings: InventoryFinding[];
}

export interface ScanProgressEvent {
  tool: string;
  status: 'running' | 'done' | 'error' | 'skipped' | 'start' | 'completed' | 'failed' | 'cancelled';
  message: string;
  count: number;
  ts: string;
  domain?: string;
  phase?: string;
  phase_index?: number;
  phase_total?: number;
  completed_tools?: number;
  total_tools?: number;
  overall_completed_tools?: number;
  overall_total_tools?: number;
}

export interface ToolApiKeysConfig {
  pdcp_api_key: string;
  github_token: string;
  shodan_api_key: string;
  censys_api_id: string;
  censys_api_secret: string;
  chaos_key: string;
  wpscan_api_token: string;
  google_cse_api_key: string;
  google_cse_cx: string;
  openai_api_key: string;
  anthropic_api_key: string;
  google_ai_api_key: string;
  deepseek_api_key: string;
  groq_api_key: string;
}
