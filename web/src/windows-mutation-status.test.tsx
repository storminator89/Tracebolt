import { setLocale } from './i18n';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach,beforeEach,describe,expect,it } from 'vitest';
import { WindowsMutationStatus } from './windows-mutation-status';
import { mutationApprovalReady,validMutationStatus,validMutationView } from './windows-mutation-status-types';
const blocked={active:true,blocked:true,domain:'managed_msi' as const,jobId:`transfer_${'1'.repeat(32)}`,phase:'dispatch_intent' as const,recovery:'intervention_required' as const,revision:'7',retained:1};
beforeEach(()=>setLocale('en',false));
afterEach(cleanup);
describe('shared mutation status',()=>{
 it('keeps exact blocked owner and original recovery truth',()=>{render(<WindowsMutationStatus status={blocked} capturedAt={100} serverNow={100}/>);expect(screen.getByRole('status').textContent).toContain('MSI');expect(screen.getByRole('status').textContent).toContain(blocked.jobId.slice(-8));expect(screen.getByText(blocked.jobId)).toBeTruthy();expect(screen.getByText('Review recovery')).toBeTruthy()});
 it('labels stale observations and rejects malformed idle/owner claims',()=>{render(<WindowsMutationStatus status={blocked} capturedAt={100} serverNow={161}/>);expect(screen.getByRole('status').textContent).toContain('Saved shared status');expect(validMutationStatus(blocked)).toBe(true);expect(validMutationStatus({...blocked,phase:'idle'})).toBe(false);expect(validMutationStatus({...blocked,domain:'cached_wua'})).toBe(false);expect(validMutationStatus({...blocked,revision:'18446744073709551616'})).toBe(false)});
 it('requires paired provenance and original bounded capture',()=>{expect(validMutationView({},100)).toBe(true);expect(validMutationView({coordinated:true,mutation:blocked,mutationCapturedAt:100},100)).toBe(true);expect(validMutationView({mutation:blocked,mutationCapturedAt:100},100)).toBe(false);expect(validMutationView({coordinated:true,mutation:blocked,mutationCapturedAt:101},100)).toBe(false)})
});
it('requires fresh active idle evidence only for coordinated approval',()=>{
 const idle={active:true,blocked:false,phase:'idle' as const,revision:'9',retained:1};
 expect(mutationApprovalReady({},100)).toBe(true);expect(mutationApprovalReady({coordinated:true},100)).toBe(false);expect(mutationApprovalReady({coordinated:true,mutation:blocked,mutationCapturedAt:100},100)).toBe(false);expect(mutationApprovalReady({coordinated:true,mutation:idle,mutationCapturedAt:100},159.9)).toBe(true);expect(mutationApprovalReady({coordinated:true,mutation:idle,mutationCapturedAt:100},160)).toBe(false);
});
