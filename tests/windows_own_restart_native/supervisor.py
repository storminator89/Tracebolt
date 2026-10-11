"""Bounded, non-killing observation. Post-launch faults cannot unwind a live child.
Deadline/cancellation/overflow permanently poison success, with bounded parallel
readers continuing to drain stdout/stderr/private report until verified exit.
"""
from __future__ import annotations
import os
import threading
import time
from contract import Rejected

class Outcome:
    def __init__(self):
        self.unknown=False; self.reason=None; self.report=bytearray(); self.returncode=None
        self.counts={'stdout':0,'stderr':0,'report':0}; self.notified=False
        self.lock=threading.Lock()
    def poison(self,reason):
        with self.lock:
            self.unknown=True
            if self.reason is None:self.reason=reason


def drain(proc,pipes,budget,cancelled,cancel_child,notify,check_live=None,limit=65536,inspect_report=None):
    """No terminate/kill/communicate, hard child timeout or kill-on-close job.
    Blocking readers need no platform nonblocking setup. Their memory is bounded
    independently of child output and they discard overflow rather than block the
    child. Callback/poll/read failures latch unknown, never unwind a live child.
    If poll cannot establish exit, observation continues for human intervention.
    """
    out=Outcome();done={name:threading.Event() for name in pipes};readers={};ended=None;cancel_sent=False
    def pump(name,fd):
        try:
            while True:
                try:chunk=os.read(fd,4096)
                except BlockingIOError:
                    time.sleep(0.01);continue
                if not chunk:break
                with out.lock:
                    out.counts[name]+=len(chunk)
                    if out.counts[name]>limit:
                        out.unknown=True
                        if out.reason is None:out.reason='output_overflow'
                    if name=='report' and len(out.report)<limit:out.report.extend(chunk[:limit-len(out.report)])
                    report_bytes=bytes(out.report) if name=='report' else None
                if report_bytes is not None and inspect_report is not None:
                    try:inspect_report(report_bytes)
                    except BaseException:out.poison('invalid_or_unknown_report')
        except BaseException:out.poison('pipe_lost')
        finally:done[name].set()
    while True:
        # Resource failures starting a reader are also irreversible unknown. A
        # later safe read-only retry is allowed; no process launch is retried.
        for name,fd in pipes.items():
            if name not in readers:
                try:
                    thread=threading.Thread(target=pump,args=(name,fd),daemon=True)
                    thread.start();readers[name]=thread
                except BaseException:out.poison('pipe_observer_unavailable')
        try:
            budget.check()
            if cancelled():out.poison('cancelled')
            if check_live:check_live()
        except BaseException as error:out.poison(error.reason if isinstance(error,Rejected) else 'observation_lost')
        if out.unknown:
            if not cancel_sent:
                try:cancel_child();cancel_sent=True
                except BaseException:out.poison('cancellation_unavailable')
            if not out.notified:
                out.notified=True
                try:notify('UNKNOWN_INTERVENTION_REQUIRED: observation only; started controller is not terminated.')
                except BaseException:out.poison('notice_unavailable')
        try:code=proc.poll()
        except BaseException:
            code=None;out.poison('process_observer_unavailable')
        if code is not None:
            out.returncode=code
            if ended is None:ended=time.monotonic()
            if all(event.is_set() for event in done.values()):break
            if time.monotonic()-ended>5:
                out.poison('pipe_not_closed');break
        try:time.sleep(0.025)
        except BaseException:out.poison('cancelled')
    # Child is known exited. This cannot become successful after a late return.
    try:
        budget.check()
        if cancelled():out.poison('cancelled')
    except BaseException:out.poison('deadline')
    return out
