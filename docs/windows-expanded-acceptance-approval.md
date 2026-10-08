# Expanded Windows native acceptance: future approval packet

Status: source-only preparation. No native run, host grant, service change,
identity creation, publication or release is authorized by this packet.
The candidate is based on `fa2a87ce13ce546c152937c804c6fd5cf9314f82`;
that base commit does not contain the new option and is not the eventual
approved source. Review the composed candidate and its full CI before assigning
its exact 40-lowercase-hex published commit to `expected_source_sha`.
No pending approval can be reused for another commit.

## Human decision to request later, after source verification

Name the exact reviewed source commit, the workflow
`Manual disposable Windows native acceptance subset`, and one fresh disposable
GitHub-hosted `windows-2025` x64 runner. Choose TLS (recommended) or explicitly
acknowledged loopback HTTP-test. No production endpoint, user computer, external
manager, tunnel or remote-control connection is part of this option.

The request must disclose and separately capture all applicable workflow inputs:

1. Original base inventory metadata, services, temporary endpoint identity,
   app-only private ACLs, loopback transport and owned cleanup, unchanged from
   the existing manual gate. The identity creates protected persistent-on-runner
   endpoint key material; it and the authority are discarded only through
   verified cleanup/runner disposal. Root/issuer material stays process-memory-only.
2. Each additional event-header, caller-visible-volume, process CPU/RAM and
   numeric TCP/UDP endpoint scope, with its explicit exclusions and bounded
   observations described in the acceptance guide.
3. Four temporary protected sibling consent stores, created only after the
   same identity activates and its owned service is stopped; their exact
   object-ID/hash-bound cleanup is included in those additional approvals.
4. If HTTP-test is selected: invitation, enrollment and every selected metadata
   scope travel in plaintext; signed requests provide neither encryption nor
   server authentication. TLS remains the default and does not imply downgrade.
5. Failure/cancellation may retain unknown/indeterminate resources and a stopped
   service until runner disposal. Never repair ACLs, adopt leftovers or relax a
   prerequisite to obtain a pass. A retained cleanup result is a failed run.

The four new checkboxes must be all true for expanded acceptance; all false
means the existing base-only option. There is no automatic matrix or fallback.
The command wrapper independently verifies dispatch/runner/repository, exact
clean checkout, GitHub and compiled source, artifact hashes and every approval.
The main controller is bounded to ten minutes, with a separate two-minute
failure cleanup interval and a twenty-minute in-memory approval lifetime.

## Evidence required before declaring a subset pass

Retain only the revalidated finite schema-v3 JSON report (three-day artifact
retention), all fourteen lifecycle checks, same-identity outage/retry/recovery,
base inventory quality, all-four v5 observation counts/qualities, real CPU delta
beyond first sample, a retained TCP loopback row matching the peer’s listening
port, limited SCM token, unrelated-service access denial, uninstall
state retention and verified owned cleanup. No raw telemetry, private paths,
keys, certificate material, host names, addresses, event content or metric values
may be published. Missing, denied and unavailable measurements stay explicit.

A pass is only a native service/loopback subset. Keep these unproven:

- Windows → production Linux manager/ingress/durable store → authenticated browser
- The fresh combined read-setup installer flow (`freshOrchestrationAcceptance=false`)
  and human hidden-console enrollment
- Separate native v2/v3/v4 configurations, all hardware/quotas/denied/removable cases
- Grant disable/replacement runtime acceptance, OS shutdown/reboot/power loss
- Desktop Windows, ARM64 native operation, released installer and field parity

There is no dispatch command here. Ask for exact action-time human approval only
once the candidate is reviewed, publication is independently authorized and its
new exact commit and CI are verified. Do not run this packet now.

The 14 dispatch inputs fit GitHub.com’s current 25-input limit; see the
[official GitHub change](https://github.blog/changelog/2025-12-04-actions-workflow-dispatch-workflows-now-support-25-inputs/).
This does not establish compatibility with older GitHub Enterprise Server versions.
