package main

import "localrmm/internal/agentidentity"

func serviceIdentity(expected string) bool { return agentidentity.Validate(expected) }
