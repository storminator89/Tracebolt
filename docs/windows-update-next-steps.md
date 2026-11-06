# Saved Windows update next steps

The selected update job view has a collapsed English/German next-step guide.
It explains the saved readiness reason, result, fixed schedule and retirement
state without deriving a new outcome from numeric codes or cached inventory.
The exact job ID and update GUID/revision stay visible inside the guide.

“Read this job again” reuses the existing authenticated, validated exact-ID GET.
It does not request readiness, approve, retry, reschedule, retire, restart or
change any host permission. Reads retain the existing byte/time bounds and hide
old evidence until they succeed. All existing session, visibility, navigation,
expiry and late-response clearing still apply. There is no polling or storage.

An unresolved tracked write or retirement-storage failure suppresses this extra
button and directs the operator to the existing “Read saved status” control.
That control retains its original exact uncertain-action reference, even while
another saved job is being inspected. Guidance never clears an uncertainty
anchor or restores an acknowledgement. Existing read/review/write admission is
unchanged.

Failed, uncertain and not-attempted results do not offer a retry or unlock.
Closing remains separate, explicitly reviewed successful-result retirement;
canceled/expired schedules do not refund occupied reusable slots. Restart or
executor intervention requires its own approval and is not performed here.

This complements local saved-history filters (#267), raw installation-result
evidence (#284) and fleet saved-history browsing (#289), without adding those
features or another job engine. Source/DOM checks are not real-session, browser,
native Windows, deployment or release acceptance.
