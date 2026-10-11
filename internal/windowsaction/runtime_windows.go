//go:build windows

package windowsaction

import (
	"context"
	"golang.org/x/sys/windows/svc"
)

func RunService() error {
	ok, e := svc.IsWindowsService()
	if e != nil || !ok {
		return ErrUnavailable
	}
	return svc.Run(BrokerName, &serviceHandler{})
}

type serviceHandler struct{}

func (*serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	current := svc.Status{State: svc.StartPending}
	status <- current
	b, closeStore, e := OpenNativeBroker()
	if e != nil {
		return false, 1
	}
	defer closeStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readySignal := make(chan struct{})
	var ready <-chan struct{} = readySignal
	done := make(chan error, 1)
	go func() { done <- serveReady(ctx, b, readySignal) }()
	for {
		select {
		case <-ready:
			ready = nil
			current = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			status <- current
		case runErr := <-done:
			return false, serviceExitCode(false, runErr, closeStore())
		case r, ok := <-requests:
			if !ok {
				cancel()
				runErr := <-done
				return false, serviceExitCode(false, runErr, closeStore())
			}
			switch r.Cmd {
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				runErr := <-done
				return false, serviceExitCode(true, runErr, closeStore())
			case svc.Interrogate:
				status <- current
			}
		}
	}
}
