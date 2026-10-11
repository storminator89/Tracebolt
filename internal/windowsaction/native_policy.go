package windowsaction

import (
	"strconv"
	"strings"
)

const brokerQueryRights uint32 = 0x20005 // READ_CONTROL, QUERY_CONFIG, QUERY_STATUS.
const serviceAllRights uint32 = 0x000f01ff

type serviceACE struct {
	SID         string
	Mask        uint32
	Kind, Flags byte
}

// The broker's service object must not be a route from an observation token to
// the broker SID. Only SYSTEM/Administrators may reconfigure/control it; both
// fixed service SIDs have exactly the query rights needed for mutual IPC proof.
func validateBrokerServiceACL(owner string, protected bool, entries []serviceACE, broker, agent string) error {
	if !validSID(broker) || !validSID(agent) || broker == agent || !protected || (owner != "S-1-5-18" && owner != "S-1-5-32-544") || len(entries) != 4 {
		return ErrBinding
	}
	required := map[string]uint32{"S-1-5-18": serviceAllRights, "S-1-5-32-544": serviceAllRights, broker: brokerQueryRights, agent: brokerQueryRights}
	for _, e := range entries {
		mask, ok := required[e.SID]
		if !ok || e.Mask != mask || e.Kind != 0 || e.Flags != 0 {
			return ErrBinding
		}
		delete(required, e.SID)
	}
	if len(required) != 0 {
		return ErrBinding
	}
	return nil
}

// Independent securable objects must not turn a query peer into a token/handle
// thief or executable thread writer. Generic, callback, inherited and deny ACE
// semantics are not guessed. No runtime permission repair occurs.
func validateKernelACL(owner string, entries []serviceACE, broker, kind, logon string) error {
	trusted := func(s string) bool { return s == broker || s == "S-1-5-18" || s == "S-1-5-32-544" }
	if !validSID(broker) || logon != "" && !validLogonSID(logon) || !trusted(owner) || len(entries) == 0 || len(entries) > 64 {
		return ErrBinding
	}
	var read uint32
	switch kind {
	case "process":
		read = 0x00121400 // SYNCHRONIZE, READ_CONTROL, query/limited query.
	case "token":
		read = 0x00020008 // READ_CONTROL, TOKEN_QUERY only.
	case "thread":
		read = 0x00120840 // SYNCHRONIZE, READ_CONTROL, query/limited query.
	case "default":
		read = 0x00020000 // Across future object types, only READ_CONTROL is safe.
	default:
		return ErrBinding
	}
	brokerAccess := false
	for _, e := range entries {
		if e.Kind != 0 || e.Flags != 0 {
			return ErrBinding
		}
		if e.SID == broker {
			brokerAccess = true
		}
		// SERVICE_SID_TYPE_RESTRICTED adds this ACE to the token object only.
		// The SID is derived from the already verified dedicated broker token,
		// never supplied by policy, IPC or an arbitrary S-1-5-5 prefix match.
		if kind == "token" && logon != "" && e.SID == logon && (e.Mask == 0x10000000 || e.Mask == 0x000f01ff) {
			continue
		}
		if !trusted(e.SID) && e.Mask & ^read != 0 {
			return ErrBinding
		}
	}
	if !brokerAccess {
		return ErrBinding
	}
	return nil
}

// These attributes are fixed Windows token-group constants, also usable in inert
// admission fixtures. A shared service account is not a broker logon identity.
type tokenGroup struct {
	SID        string
	Attributes uint32
}

func validLogonSID(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 6 || strings.Join(parts[:4], "-") != "S-1-5-5" {
		return false
	}
	nonzero := false
	for _, p := range parts[4:] {
		n, e := strconv.ParseUint(p, 10, 32)
		if e != nil || strconv.FormatUint(n, 10) != p {
			return false
		}
		nonzero = nonzero || n != 0
	}
	return nonzero
}
func brokerLogonSID(user, broker string, groups []tokenGroup) (string, error) {
	if user != broker || !validSID(broker) || len(groups) == 0 || len(groups) > 128 {
		return "", ErrBinding
	}
	found := ""
	for _, g := range groups {
		hasLogon := g.Attributes&0xc0000000 != 0
		if hasLogon || strings.HasPrefix(g.SID, "S-1-5-5-") {
			if found != "" || !validLogonSID(g.SID) || g.Attributes != 0xc0000007 {
				return "", ErrBinding
			}
			found = g.SID
		}
	}
	if found == "" {
		return "", ErrBinding
	}
	return found, nil
}
