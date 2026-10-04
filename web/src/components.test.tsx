import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Dialog, EvidenceCard, MetricValue, Source, Status } from './components';
import type { Evidence, Metric } from './types';
afterEach(cleanup);
describe('truthful telemetry',()=>{
  it('shows absent observations as unavailable rather than zero',()=>{render(<MetricValue metric={{value:null,unit:'%',quality:'unknown',source:'none',collectedAt:'2026-10-03T12:00:00Z'}}/>);expect(screen.getByText('—')).toBeVisible();expect(screen.getByText('Nicht verfügbar')).toBeVisible();expect(screen.queryByText('0')).not.toBeInTheDocument();});
  it('marks a fresh 99% value as resource danger, not healthy consumption',()=>{const {container}=render(<MetricValue metric={{value:99,unit:'%',quality:'healthy',source:'fixture',collectedAt:'2026-10-03T12:00:00Z'} as Metric}/>);expect(container.querySelector('.meter-track .danger')).toBeInTheDocument();expect(screen.getByText('Aktuell')).toBeInTheDocument();});
  it('distinguishes unknown, stale, and source provenance',()=>{render(<><Status status="unknown"/><Status status="stale"/><Source synthetic={true}/><Source synthetic={false}/></>);expect(screen.getByText('Unbekannt')).toBeVisible();expect(screen.getByText('Veraltet')).toBeVisible();expect(screen.getByText('Demo')).toBeVisible();expect(screen.getByText('Lokale Quelle')).toBeVisible();});
});
describe('untrusted evidence rendering',()=>{
  it('renders injected markup as inert text, never img or script DOM',()=>{const attack='<img src=x onerror=alert(1)><script>alert(1)</script>';const evidence:Evidence={id:'test',title:attack,source:attack,quality:'unknown',collectedAt:'2026-10-03T12:00:00Z',detail:attack,value:attack,synthetic:true};const {container}=render(<EvidenceCard evidence={evidence} index={0}/>);fireEvent.click(container.querySelector('summary')!);expect(container.querySelector('img')).not.toBeInTheDocument();expect(container.querySelector('script')).not.toBeInTheDocument();expect(container.textContent).toContain(attack);});
});
describe('accessible dialog',()=>{
  it('closes with Escape and restores prior focus',()=>{const close=vi.fn();const before=document.createElement('button');document.body.append(before);before.focus();const {unmount}=render(<Dialog title="Test" onClose={close}><button>Action</button></Dialog>);expect(screen.getByRole('dialog')).toHaveFocus();fireEvent.keyDown(document,{key:'Escape'});expect(close).toHaveBeenCalledOnce();unmount();expect(before).toHaveFocus();before.remove();});
  it('does not close when clicking content',()=>{const close=vi.fn();render(<Dialog title="Test" onClose={close}><p>Inside</p></Dialog>);fireEvent.mouseDown(screen.getByText('Inside'));expect(close).not.toHaveBeenCalled();});
});

describe('LAN health is separate from observation contact',()=>{
  it('labels unassessed real LAN health without pretending it is healthy or disconnected',()=>{render(<Status status="unknown" source="lan" synthetic={false}/>);expect(screen.getByText('Nicht bewertet')).toBeVisible();expect(screen.getByText('Nicht bewertet')).toHaveAttribute('title',expect.stringContaining('letzten Beobachtung'));expect(screen.queryByText('Unauffällig')).not.toBeInTheDocument();expect(screen.queryByText('Offline')).not.toBeInTheDocument();});
  it('preserves unknown for synthetic and non-LAN sources',()=>{render(<><Status status="unknown" source="lan" synthetic/><Status status="unknown" source="sandbox"/></>);expect(screen.getAllByText('Unbekannt')).toHaveLength(2);});
});
