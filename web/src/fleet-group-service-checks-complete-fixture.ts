import type { GroupCompleteServiceChecksView, GroupCompleteServiceChoiceView } from './fleet-group-service-checks-complete-workflow';
import fixture from './windows-complete-group-service-go-fixture.json';
import { validGroupCompleteServiceChecksView, validGroupCompleteServiceChoiceView } from './fleet-group-service-checks-complete-workflow';
/** Exact handler-generated invented DTOs. No native observation or grant. */
export function completeGroupServiceFixture(): GroupCompleteServiceChecksView {
    const view = structuredClone(fixture.overview);
    if (!validGroupCompleteServiceChecksView(view, view.groupId)) throw new Error('Invalid exported complete group fixture');
    return view;
}
export function completeGroupServiceChoiceFixture(configured = false): GroupCompleteServiceChoiceView {
    const view = structuredClone(configured ? fixture.configured : fixture.choice);
    if (!validGroupCompleteServiceChoiceView(view, view.groupId, view.member.key)) throw new Error('Invalid exported complete choice fixture');
    return view;
}
