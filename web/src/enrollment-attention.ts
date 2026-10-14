import type { EnrollmentCollectionProfile, EnrollmentPlatform } from './enrollment-types';

// Presentation only. Enrollment owns all source snapshots, clocks, consent and
// actions. Never add an invitation/device ID, secret, callback or permission here.
export type EnrollmentAttention = {
    platform: EnrollmentPlatform;
    profile: EnrollmentCollectionProfile | null;
    state: 'checking' | 'unknown' | 'unavailable' | 'manual' | 'pending-review' | 'unconfirmed' | 'expired' | 'retained-review';
    pendingCount: number | null;
};
