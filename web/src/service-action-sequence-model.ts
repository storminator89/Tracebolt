import { affectedServicesDigest } from './service-action-impact';
import type { ServiceActionPreview, ServiceActionView } from './service-action-types';

export const maxServiceSequenceSteps = 8;
export type ServiceSequenceStep = ServiceActionView['services'][number];
export type ServiceSequenceBinding = Pick<ServiceActionPreview, 'version' | 'scope' | 'reviewNotice' | 'deviceId' | 'actorId' | 'incarnationDigest' | 'rootPolicyDigest' | 'keyId' | 'transportProfile'>;
export function sequenceBinding(preview: ServiceActionPreview): ServiceSequenceBinding {
    const { version, scope, reviewNotice, deviceId, actorId, incarnationDigest, rootPolicyDigest, keyId, transportProfile } = preview;
    return { version, scope, reviewNotice, deviceId, actorId, incarnationDigest, rootPolicyDigest, keyId, transportProfile };
}
export function sameSequenceBinding(preview: ServiceActionPreview, binding: ServiceSequenceBinding): boolean {
    return JSON.stringify(sequenceBinding(preview)) === JSON.stringify(binding);
}
export function sequenceStepsMatch(steps: readonly ServiceSequenceStep[], view: ServiceActionView): boolean {
    return steps.length > 0 && steps.length <= maxServiceSequenceSteps && new Set(steps.map(step => step.unit)).size === steps.length
        && steps.every(step => view.services.some(current => current.unit === step.unit && current.unitPolicyDigest === step.unitPolicyDigest
            && JSON.stringify(current.affectedServices) === JSON.stringify(step.affectedServices)));
}
export function sequencePreviewMatches(preview: ServiceActionPreview, step: ServiceSequenceStep, binding: ServiceSequenceBinding): boolean {
    return sameSequenceBinding(preview, binding) && preview.plan.unit === step.unit && preview.plan.unitPolicyDigest === step.unitPolicyDigest
        && (preview.version === 'tracebolt.service-action-preview.v1' ? step.affectedServices === undefined
            : !!step.affectedServices && JSON.stringify(preview.affectedServices) === JSON.stringify(step.affectedServices)
                && preview.plan.affectedServicesDigest === affectedServicesDigest(step.affectedServices));
}
