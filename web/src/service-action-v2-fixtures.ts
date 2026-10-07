import { actionPreview, actionView } from './service-action-fixtures';
import { affectedServicesDigest } from './service-action-impact';
import { serviceActionReviewNotice, serviceActionScope } from './service-action-types';
import type { ServiceActionView, ServiceActionPreview } from './service-action-types';
export function actionV2Preview(affectedServices = ['dependent.service', 'fixture.service']): ServiceActionPreview {
    const old = actionPreview();
    return { ...old, version: 'tracebolt.service-action-preview.v2', scope: serviceActionScope, reviewNotice: serviceActionReviewNotice, affectedServices, plan: { ...old.plan, version: 'tracebolt.action-plan.v2', affectedServicesDigest: affectedServicesDigest(affectedServices) } };
}
export function actionV2View(affectedServices = ['dependent.service', 'fixture.service']): ServiceActionView {
    const preview = actionV2Preview(affectedServices);
    return { ...actionView(), schemaVersion: 'tracebolt.service-action-view.v2', scope: serviceActionScope, reviewNotice: serviceActionReviewNotice, services: [{ unit: preview.plan.unit, unitPolicyDigest: preview.plan.unitPolicyDigest, affectedServices }], preview, excludedServices: [{ unit: 'tracebolt-agent.service', reason: 'control_plane_protected' }] };
}
