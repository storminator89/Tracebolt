export type Platform = 'windows' | 'linux' | 'macos';
export type Quality = 'healthy' | 'stale' | 'unknown' | 'denied';
export type DeviceStatus = 'healthy' | 'attention' | 'critical' | 'stale' | 'unknown';
export interface Metric { value: number | null; unit: string; quality: Quality; source: string; collectedAt: string }
export interface Evidence { id: string; title: string; source: string; quality: Quality; collectedAt: string; detail: string; value: string; synthetic: boolean }
export interface Capability { id: string; name: string; status: 'supported' | 'limited' | 'unsupported' | 'denied'; detail: string }
export interface Device { id: string; name: string; platform: Platform; os: string; site: string; group: string; ip: string | null; status: DeviceStatus; source: 'synthetic' | 'sandbox' | 'local'; synthetic: boolean; lastSeen: string; agentVersion: string; cpu: Metric; memory: Metric; disk: Metric; uptime: string; tags: string[]; capabilities: Capability[]; evidence: Evidence[]; trend: number[]; caseIds: string[] }
export interface Activity { id: string; type: 'observation' | 'case' | 'note' | 'status'; title: string; detail: string; time: string; deviceId?: string; caseId?: string }
export interface Note { id: string; text: string; createdAt: string; author: string }
export interface Case { id: string; title: string; deviceId: string; deviceName: string; severity: 'critical' | 'warning' | 'info'; status: 'open' | 'investigating' | 'resolved'; category: 'service' | 'storage' | 'network'; summary: string; ruleId: string; confidence: 'evidence-backed' | 'limited'; createdAt: string; updatedAt: string; evidenceIds: string[]; evidence: Evidence[]; runbookId: string; nextSteps: string[]; timeline: Activity[]; notes: Note[]; synthetic: boolean }
export interface Overview { product: string; mode: string; generatedAt: string; stats: { totalDevices: number; healthyDevices: number; attentionDevices: number; unknownDevices: number; openCases: number; criticalCases: number }; devices: Device[]; cases: Case[]; activity: Activity[] }
export interface Capabilities { mode: string; syntheticFleet: boolean; realCollector: string; remoteEnrollment: boolean; shellExecution: boolean; aiConnected: boolean; persistence: string; limitations: string[]; version?: string }
export type View = 'overview' | 'devices' | 'cases' | 'settings';
