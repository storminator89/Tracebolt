export const savedMSIFixture = {
  "worklist": {
    "id": "worklist_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "revision": 3,
    "serverNow": 1791799200,
    "name": "SYNTHETIC · Desktop package 1.2.3",
    "createdBy": "operator_cccccccccccccccccccccccccccccccc",
    "createdAt": 1791799080,
    "archivedAt": 0,
    "artifactId": "sha256:272adeb41c0ad946d017e15686ce050ea9c22f0375a93d23b80cab670e9a3857",
    "artifactRetiredCount": "0",
    "package": {
      "sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "size": 1048576,
      "productCode": "{11111111-2222-3333-4444-555555555555}",
      "packageCode": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
      "version": "1.2.3",
      "architecture": "amd64",
      "name": "Synthetic reviewed machine package",
      "termsReviewDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "reviewReference": "Invented source-only package review; no MSI bytes"
    },
    "nativeAcceptanceDigest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
    "publisherStatus": "unverified",
    "publisherEvidenceDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "group": {
      "id": "group_ffffffffffffffffffffffffffffffff",
      "name": "SYNTHETIC · Frozen pilot cohort",
      "revision": 7
    },
    "targets": [
      {
        "name": "SYNTHETIC · Berlin MSI target",
        "binding": {
          "managerId": "manager_11111111111111111111111111111111",
          "deviceId": "agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "incarnationDigest": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
          "executorId": "executor_22222222222222222222222222222222",
          "executorKeyId": "sha256:8888888888888888888888888888888888888888888888888888888888888888",
          "keyId": "sha256:9999999999999999999999999999999999999999999999999999999999999999",
          "deliveryGrantId": "grant_33333333333333333333333333333333",
          "installGrantId": "grant_66666666666666666666666666666666"
        },
        "transferId": "",
        "jobSequence": "0"
      },
      {
        "name": "SYNTHETIC · Hamburg saved result",
        "binding": {
          "managerId": "manager_11111111111111111111111111111111",
          "deviceId": "agent_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "incarnationDigest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
          "executorId": "executor_33333333333333333333333333333333",
          "executorKeyId": "sha256:8888888888888888888888888888888888888888888888888888888888888888",
          "keyId": "sha256:9999999999999999999999999999999999999999999999999999999999999999",
          "deliveryGrantId": "grant_44444444444444444444444444444444",
          "installGrantId": "grant_77777777777777777777777777777777"
        },
        "transferId": "",
        "jobSequence": "0"
      },
      {
        "name": "SYNTHETIC · Munich unavailable target",
        "binding": {
          "managerId": "manager_11111111111111111111111111111111",
          "deviceId": "agent_dddddddddddddddddddddddddddddddd",
          "incarnationDigest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
          "executorId": "executor_44444444444444444444444444444444",
          "executorKeyId": "sha256:8888888888888888888888888888888888888888888888888888888888888888",
          "keyId": "sha256:9999999999999999999999999999999999999999999999999999999999999999",
          "deliveryGrantId": "grant_55555555555555555555555555555555",
          "installGrantId": "grant_88888888888888888888888888888888"
        },
        "transferId": "transfer_dddddddddddddddddddddddddddddddd",
        "jobSequence": "1"
      }
    ],
    "batches": [],
    "rows": [
      {
        "deviceId": "agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "available": true,
        "state": "not_dispatched",
        "view": {
          "version": "tracebolt.windows-managed-msi.v1",
          "deviceId": "agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "serverNow": 1791799200,
          "state": "uploaded",
          "artifactId": "sha256:272adeb41c0ad946d017e15686ce050ea9c22f0375a93d23b80cab670e9a3857",
          "bindingDigest": "sha256:8ae92925e148450ddfcc61e0e6054651bafd4adb45fb7f44f44462a6e949e13c",
          "package": {
            "sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "size": 1048576,
            "productCode": "{11111111-2222-3333-4444-555555555555}",
            "packageCode": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            "version": "1.2.3",
            "architecture": "amd64",
            "name": "Synthetic reviewed machine package",
            "termsReviewDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "reviewReference": "Invented source-only package review; no MSI bytes"
          },
          "nativeAcceptanceDigest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
          "transferId": "",
          "readinessDigest": "",
          "expiresAt": 0,
          "readiness": null,
          "result": null,
          "uploadOffset": 1048576,
          "uploadPendingDigest": "",
          "canReview": false,
          "reusable": true,
          "artifactRetiredCount": "0",
          "coordinated": true,
          "publisherStatus": "unverified",
          "publisherEvidenceDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "jobSequence": "0",
          "retiredFloor": "0",
          "grantExpiresAt": 1791801000,
          "canRetire": false,
          "mutationCapturedAt": 1791799200,
          "mutation": {
            "active": true,
            "blocked": false,
            "phase": "idle",
            "revision": "8",
            "retained": 0
          }
        }
      },
      {
        "deviceId": "agent_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "available": true,
        "state": "not_dispatched",
        "view": {
          "version": "tracebolt.windows-managed-msi.v1",
          "deviceId": "agent_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "serverNow": 1791799200,
          "state": "uploaded",
          "artifactId": "sha256:272adeb41c0ad946d017e15686ce050ea9c22f0375a93d23b80cab670e9a3857",
          "bindingDigest": "sha256:c76e9e0f49787a277f0176b988cdb06522fb7bc966edd33e62feb37cf4826b59",
          "package": {
            "sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "size": 1048576,
            "productCode": "{11111111-2222-3333-4444-555555555555}",
            "packageCode": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            "version": "1.2.3",
            "architecture": "amd64",
            "name": "Synthetic reviewed machine package",
            "termsReviewDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "reviewReference": "Invented source-only package review; no MSI bytes"
          },
          "nativeAcceptanceDigest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
          "transferId": "",
          "readinessDigest": "",
          "expiresAt": 0,
          "readiness": null,
          "result": null,
          "uploadOffset": 1048576,
          "uploadPendingDigest": "",
          "canReview": false,
          "coordinated": true,
          "mutationCapturedAt": 1791799200,
          "mutation": {
            "active": true,
            "blocked": false,
            "phase": "idle",
            "revision": "8",
            "retained": 0
          },
          "reusable": true,
          "artifactRetiredCount": "0",
          "publisherStatus": "unverified",
          "publisherEvidenceDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "jobSequence": "0",
          "retiredFloor": "0",
          "grantExpiresAt": 1791801000,
          "canRetire": false
        }
      },
      {
        "deviceId": "agent_dddddddddddddddddddddddddddddddd",
        "available": false,
        "state": "unavailable",
        "historicalOutcome": "succeeded"
      }
    ]
  },
  "artifact": {
    "version": "tracebolt.windows-managed-msi-artifact.v3",
    "serverNow": 1791799200,
    "state": "uploaded",
    "artifactId": "sha256:272adeb41c0ad946d017e15686ce050ea9c22f0375a93d23b80cab670e9a3857",
    "package": {
      "sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "size": 1048576,
      "productCode": "{11111111-2222-3333-4444-555555555555}",
      "packageCode": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
      "version": "1.2.3",
      "architecture": "amd64",
      "name": "Synthetic reviewed machine package",
      "termsReviewDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "reviewReference": "Invented source-only package review; no MSI bytes"
    },
    "nativeAcceptanceDigest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
    "uploadOffset": 1048576,
    "uploadPendingDigest": "",
    "targets": [
      {
        "deviceId": "agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bindingDigest": "sha256:8ae92925e148450ddfcc61e0e6054651bafd4adb45fb7f44f44462a6e949e13c"
      },
      {
        "deviceId": "agent_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "bindingDigest": "sha256:c76e9e0f49787a277f0176b988cdb06522fb7bc966edd33e62feb37cf4826b59"
      },
      {
        "deviceId": "agent_dddddddddddddddddddddddddddddddd",
        "bindingDigest": "sha256:f4bb6b35ee6db7d01bf58323c445d66586b2dc581749e978d469eb995b37f21e"
      }
    ],
    "reusable": true,
    "publisherStatus": "unverified",
    "publisherEvidenceDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "retiredCount": "0",
    "maxRetainedPayloadBytes": 134217728,
    "canRetire": false,
    "retirementBlocked": "awaiting_device_retirement"
  },
  "devices": [
    {
      "id": "agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "name": "SYNTHETIC · Berlin MSI target",
      "platform": "windows",
      "os": "Windows fixture",
      "source": "lan",
      "synthetic": false,
      "status": "unknown",
      "site": "",
      "group": "",
      "ip": null,
      "lastSeen": "2026-10-12T10:00:00.000Z",
      "agentVersion": "source-fixture",
      "cpu": {
        "value": 24,
        "unit": "%",
        "quality": "healthy",
        "source": "Synthetic Windows metric",
        "collectedAt": "2026-10-07T12:00:00Z"
      },
      "memory": {
        "value": 51,
        "unit": "%",
        "quality": "healthy",
        "source": "Synthetic Windows metric",
        "collectedAt": "2026-10-07T12:00:00Z"
      },
      "disk": {
        "value": 61,
        "unit": "%",
        "quality": "healthy",
        "source": "Synthetic Windows metric",
        "collectedAt": "2026-10-07T12:00:00Z"
      },
      "uptime": "3h",
      "tags": [],
      "capabilities": [
        {
          "id": "agent_identity",
          "name": "Enrolled agent identity",
          "status": "supported",
          "detail": "Synthetic activated identity fixture; no native enrollment or permission change"
        }
      ],
      "evidence": [],
      "trend": [],
      "caseIds": [],
      "agentCertificate": {
        "source": "guided-enrollment",
        "checkedAt": "2026-10-12T10:00:00.000Z",
        "expiresAt": "2026-10-13T10:00:00.000Z"
      }
    },
    {
      "id": "agent_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "name": "SYNTHETIC · Hamburg saved result",
      "platform": "windows",
      "os": "Windows fixture",
      "source": "lan",
      "synthetic": false,
      "status": "unknown",
      "site": "",
      "group": "",
      "ip": null,
      "lastSeen": "2026-10-12T10:00:00.000Z",
      "agentVersion": "source-fixture",
      "cpu": {
        "value": 24,
        "unit": "%",
        "quality": "healthy",
        "source": "Synthetic Windows metric",
        "collectedAt": "2026-10-07T12:00:00Z"
      },
      "memory": {
        "value": 51,
        "unit": "%",
        "quality": "healthy",
        "source": "Synthetic Windows metric",
        "collectedAt": "2026-10-07T12:00:00Z"
      },
      "disk": {
        "value": 61,
        "unit": "%",
        "quality": "healthy",
        "source": "Synthetic Windows metric",
        "collectedAt": "2026-10-07T12:00:00Z"
      },
      "uptime": "3h",
      "tags": [],
      "capabilities": [
        {
          "id": "agent_identity",
          "name": "Enrolled agent identity",
          "status": "supported",
          "detail": "Synthetic activated identity fixture; no native enrollment or permission change"
        }
      ],
      "evidence": [],
      "trend": [],
      "caseIds": [],
      "agentCertificate": {
        "source": "guided-enrollment",
        "checkedAt": "2026-10-12T10:00:00.000Z",
        "expiresAt": "2026-10-13T10:00:00.000Z"
      }
    },
    {
      "id": "agent_dddddddddddddddddddddddddddddddd",
      "name": "SYNTHETIC · Munich unavailable target",
      "platform": "windows",
      "os": "Windows fixture",
      "source": "lan",
      "synthetic": false,
      "status": "unknown",
      "site": "",
      "group": "",
      "ip": null,
      "lastSeen": "2026-10-12T10:00:00.000Z",
      "agentVersion": "source-fixture",
      "cpu": {
        "value": 24,
        "unit": "%",
        "quality": "healthy",
        "source": "Synthetic Windows metric",
        "collectedAt": "2026-10-07T12:00:00Z"
      },
      "memory": {
        "value": 51,
        "unit": "%",
        "quality": "healthy",
        "source": "Synthetic Windows metric",
        "collectedAt": "2026-10-07T12:00:00Z"
      },
      "disk": {
        "value": 61,
        "unit": "%",
        "quality": "healthy",
        "source": "Synthetic Windows metric",
        "collectedAt": "2026-10-07T12:00:00Z"
      },
      "uptime": "3h",
      "tags": [],
      "capabilities": [
        {
          "id": "agent_identity",
          "name": "Enrolled agent identity",
          "status": "supported",
          "detail": "Synthetic activated identity fixture; no native enrollment or permission change"
        }
      ],
      "evidence": [],
      "trend": [],
      "caseIds": [],
      "agentCertificate": {
        "source": "guided-enrollment",
        "checkedAt": "2026-10-12T10:00:00.000Z",
        "expiresAt": "2026-10-13T10:00:00.000Z"
      }
    }
  ],
  "session": {
    "mode": "lan",
    "transport": "https",
    "insecureTestMode": false,
    "transportWarning": null,
    "authenticationRequired": true,
    "authenticated": true,
    "csrfToken": "PUBLIC_SYNTHETIC_FLEET_MSI_CSRF",
    "serverNow": "2026-10-12T10:00:00.000Z",
    "expiresAt": "2026-10-12T11:00:00.000Z",
    "expiresInSeconds": 3600,
    "loginMode": "named",
    "actorId": "operator_cccccccccccccccccccccccccccccccc",
    "capabilities": [
      "read",
      "windows_managed_msi_deliver",
      "windows_managed_msi_install"
    ]
  },
  "preview": {
    "worklistId": "worklist_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "revision": 3,
    "kind": "deliver",
    "items": [
      {
        "deviceId": "agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "operation": "deliver",
        "artifactId": "sha256:272adeb41c0ad946d017e15686ce050ea9c22f0375a93d23b80cab670e9a3857",
        "artifactRetiredCount": "0",
        "bindingDigest": "sha256:8ae92925e148450ddfcc61e0e6054651bafd4adb45fb7f44f44462a6e949e13c",
        "transferId": "transfer_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "jobSequence": "",
        "readinessDigest": "",
        "expiresAt": 1791799260
      },
      {
        "deviceId": "agent_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "operation": "deliver",
        "artifactId": "sha256:272adeb41c0ad946d017e15686ce050ea9c22f0375a93d23b80cab670e9a3857",
        "artifactRetiredCount": "0",
        "bindingDigest": "sha256:c76e9e0f49787a277f0176b988cdb06522fb7bc966edd33e62feb37cf4826b59",
        "transferId": "transfer_77777777777777777777777777777777",
        "jobSequence": "",
        "readinessDigest": "",
        "expiresAt": 1791799260
      }
    ],
    "excluded": [
      {
        "deviceId": "agent_dddddddddddddddddddddddddddddddd",
        "reason": "unavailable"
      }
    ]
  }
};
