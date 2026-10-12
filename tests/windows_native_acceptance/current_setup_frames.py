"""Finite CURRENT21 fixture projection; no host, credential or source reads."""
import re
SCOPES = ('windows-inventory-v1', 'windows-application-system-event-headers-v1', 'windows-visible-volumes-v1', 'windows-process-metrics-v1', 'windows-network-endpoints-v1', 'windows-service-startup-v1', 'windows-complete-services-v1', 'windows-complete-machine-software-v1', 'windows-adapter-context-v1', 'windows-patch-context-v1', 'windows-security-posture-v1', 'windows-session-context-v1', 'windows-hardware-context-v1', 'windows-storage-context-v1', 'windows-security-coverage-v1', 'windows-complete-processes-v1', 'windows-network-context-v1', 'windows-resource-context-v1', 'windows-storage-io-v1', 'windows-machine-software-history-v1', 'windows-application-system-event-history-v1')
INDEPENDENT={"windows-complete-services-v1","windows-complete-machine-software-v1","windows-complete-processes-v1","windows-network-context-v1"}
GRANT_ONLY={"windows-machine-software-history-v1","windows-application-system-event-history-v1"}
QUALITIES={"observed","healthy","partial","denied","unavailable","unknown","unsupported","firstSample","reset","other"}
REASONS={"access_denied","unavailable","unsupported","source_changed","malformed_source","resource_limit","deadline","canceled"}
def need(ok):
    if not ok: raise ValueError("current frame evidence rejected")
def number(v,limit): return type(v) is int and 0<=v<=limit
def hash_or_empty(v,n): return type(v) is str and (v=="" if n==0 else re.fullmatch(r"[0-9a-f]{64}",v) is not None)
def zero_observation():
    return {"schemaVersion":"tracebolt.windows-current-fixture-observation.v1","setupContract":"fresh-twenty-one-read-admin-scopes-v1","renewalPolicy":"same-key-v1","initialCredentialGeneration":0,"acceptedFrames":0,"lastSequence":0,"v16Frames":0,"lastFrameSha256":"","sources":[{"scope":scope,"kind":"independent" if scope in INDEPENDENT else "grant_only" if scope in GRANT_ONLY else "ordinary","frames":0,"samples":0,"lastSequence":0,"lastFrameSha256":"","status":"not_run","reason":"","rowCount":0,"completeFields":0,"truncatedFields":0,"qualities":dict.fromkeys(QUALITIES,0)} for scope in SCOPES],"fullAcceptance":False,"nativeProviderProof":False,"renewalCycleProved":False}
def validate(o):
    z=zero_observation()
    need(type(o) is dict and set(o)==set(z))
    need(all(o[k]==z[k] for k in ("schemaVersion","setupContract","renewalPolicy")))
    need(all(o[k] is False for k in ("fullAcceptance","nativeProviderProof","renewalCycleProved")))
    need(number(o["initialCredentialGeneration"],1) and number(o["acceptedFrames"],64) and number(o["v16Frames"],o["acceptedFrames"]) and number(o["lastSequence"],(1<<53)-1))
    need((o["acceptedFrames"]==0)==(o["lastSequence"]==0) and hash_or_empty(o["lastFrameSha256"],o["acceptedFrames"]))
    need(o["acceptedFrames"]==0 or o["initialCredentialGeneration"]==1)
    need(type(o["sources"]) is list and len(o["sources"])==21)
    for s,base in zip(o["sources"],z["sources"]):
        need(type(s) is dict and set(s)==set(base) and s["scope"]==base["scope"] and s["kind"]==base["kind"])
        need(number(s["frames"],4096) and number(s["samples"],s["frames"]) and number(s["lastSequence"],(1<<53)-1) and number(s["rowCount"],32768) and number(s["completeFields"],100000) and number(s["truncatedFields"],100000))
        need(s["frames"] == 0 or o["initialCredentialGeneration"] == 1)
        need(hash_or_empty(s["lastFrameSha256"],s["frames"]) and (s["frames"]==0)==(s["lastSequence"]==0))
        need(type(s["qualities"]) is dict and set(s["qualities"])==QUALITIES and all(number(v,100000) for v in s["qualities"].values()))
        if s["kind"]=="grant_only" or s["frames"]==0:
            need(s==base);continue
        need(s["status"] in {"observed","scope","pending","complete","source_failed"})
        if s["kind"]=="ordinary":
            need(s["status"]=="observed" and s["frames"]==s["samples"] and s["frames"]<=o["acceptedFrames"] and s["lastSequence"]<=o["lastSequence"])
        else:
            need(s["status"] in {"scope","pending","complete","source_failed"} and s["samples"] < s["frames"])
            if s["status"] in {"scope","pending"}: need(s["rowCount"] == s["completeFields"] == s["truncatedFields"] == 0 and all(v==0 for v in s["qualities"].values()))
            if s["status"]=="scope": need(s["samples"]==0 and s["frames"]==1)
            if s["status"]=="pending": need(s["frames"]>=2)
        if s["status"]=="source_failed": need(s["reason"] in REASONS and s["samples"]>0)
        else: need(s["reason"]=="")
        if s["status"]=="complete": need(s["samples"]>0)
    return o["initialCredentialGeneration"]==1 and o["v16Frames"]>0 and all(s["kind"]=="grant_only" or s["samples"]>0 and (s["kind"]!="independent" or s["status"] in {"complete","source_failed"}) for s in o["sources"])
