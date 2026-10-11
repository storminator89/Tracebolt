package windowsaction

// FILE_APPEND_DATA is FILE_CREATE_PIPE_INSTANCE for named pipes. It is
// deliberately excluded from the observation client's explicit access mask.
const pipeClientAccess uint32 = 0x00120183

func pipeSDDL(broker, agent string) (string, error) {
	if !validSID(broker) || !validSID(agent) || broker == agent {
		return "", ErrInvalid
	}
	return "O:" + broker + "G:" + broker + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + broker + ")(A;;0x00120183;;;" + agent + ")", nil
}

// With the exact existing child chain held without delete sharing, the right
// to add an unrelated subdirectory does not permit replacing that chain. The
// same bit is append-data on files and remains forbidden there.
func untrustedPathWriteMask(directory bool) uint32 {
	const genericAll = 0x10000000
	const genericWrite = 0x40000000
	mask := uint32(genericAll | genericWrite | 0x40000 | 0x80000 | 0x10000 | 0x2 | 0x10 | 0x100)
	if directory {
		mask |= 0x40
	} else {
		mask |= 0x4
	}
	return mask
}
