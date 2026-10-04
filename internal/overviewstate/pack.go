package overviewstate

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewwire"
	"strconv"
)

const packMagic = "tracebolt.overview-spool.pack.v1\n"

type generationPack struct {
	raw    []byte
	frames [][]byte
}

func encodePayload(operation string, r diskRecord, hash string, payload []byte) ([]byte, error) {
	// All framing strings are validated generated identifiers. Keep payload exact;
	// encoding/json.RawMessage would compact whitespace in caller-provided bytes.
	raw := []byte(`{"schemaVersion":` + strconv.Quote(overviewwire.MessageVersion) + `,"section":` + strconv.Quote(r.Section) + `,"sequence":` + strconv.Quote(strconv.FormatUint(r.Floor, 10)) + `,"generationId":` + strconv.Quote(r.Generation) + `,"manifestHash":` + strconv.Quote(hash) + `,"payload":`)
	raw = append(raw, payload...)
	raw = append(raw, '}')
	if _, e := overviewwire.DecodeMessage(operation, raw); e != nil {
		return nil, ErrBody
	}
	return raw, nil
}
func buildPack(ctx context.Context, r diskRecord, manifest []byte, chunks [][]byte) (*generationPack, string, error) {
	if len(manifest) == 0 || len(manifest) > overviewgeneration.MaxManifestBytes || len(chunks) > overviewgeneration.MaxGenerationChunks {
		return nil, "", ErrBody
	}
	total := len(manifest)
	for _, raw := range chunks {
		if len(raw) == 0 || len(raw) > overviewgeneration.MaxChunkBytes || len(raw) > MaxRawBytes-total {
			return nil, "", ErrBody
		}
		total += len(raw)
	}
	m, e := overviewgeneration.DecodeManifest(manifest)
	if e != nil || m.Section != r.Section || m.GenerationID != r.Generation || m.CollectedAt.Format("2006-01-02T15:04:05.999999999Z07:00") != r.AttemptedAt || int(m.ChunkCount) != len(chunks) {
		return nil, "", ErrBody
	}
	hash, e := overviewgeneration.ManifestDigest(m)
	if e != nil {
		return nil, "", ErrBody
	}
	validator, e := overviewgeneration.NewValidator(ctx, m)
	if e != nil {
		return nil, "", ErrCanceled
	}
	// Budget and validate all chunks BEFORE building or writing a spool file.
	for _, raw := range chunks {
		if canceled(ctx) {
			return nil, "", ErrCanceled
		}
		c, e := overviewgeneration.DecodeChunk(raw)
		if e != nil {
			return nil, "", ErrBody
		}
		if e = validator.Add(c); e != nil {
			if canceled(ctx) {
				return nil, "", ErrCanceled
			}
			return nil, "", ErrBody
		}
	}
	if _, e = validator.Finish(); e != nil {
		if canceled(ctx) {
			return nil, "", ErrCanceled
		}
		return nil, "", ErrBody
	}
	var b bytes.Buffer
	b.Grow(total + (len(chunks)+2)*512)
	b.WriteString(packMagic)
	add := func(op string, payload []byte) error {
		raw, e := encodePayload(op, r, hash, payload)
		if e != nil {
			return e
		}
		if len(raw)+4 > MaxPackBytes-b.Len() {
			return ErrBody
		}
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
		b.Write(size[:])
		b.Write(raw)
		return nil
	}
	if e = add("begin", manifest); e != nil {
		return nil, "", e
	}
	for _, raw := range chunks {
		if canceled(ctx) {
			return nil, "", ErrCanceled
		}
		if e = add("append", raw); e != nil {
			return nil, "", e
		}
	}
	if e = add("finalize", []byte(`{}`)); e != nil {
		return nil, "", e
	}
	check := r
	check.ManifestHash = hash
	check.Count = m.ChunkCount
	pack, e := decodePack(ctx, b.Bytes(), check)
	return pack, hash, e
}
func decodePack(ctx context.Context, raw []byte, r diskRecord) (*generationPack, error) {
	if len(raw) > MaxPackBytes || !bytes.HasPrefix(raw, []byte(packMagic)) {
		return nil, ErrCorrupt
	}
	p := &generationPack{raw: raw}
	rest := raw[len(packMagic):]
	var validator *overviewgeneration.Validator
	total := 0
	for index := uint32(0); index < r.Count+2; index++ {
		if canceled(ctx) {
			return nil, ErrCanceled
		}
		if len(rest) < 4 {
			return nil, ErrCorrupt
		}
		size := binary.BigEndian.Uint32(rest)
		rest = rest[4:]
		if size == 0 || size > overviewwire.MaxBodyBytes || uint64(size) > uint64(len(rest)) {
			return nil, ErrCorrupt
		}
		body := rest[:int(size):int(size)]
		rest = rest[int(size):]
		op := "append"
		if index == 0 {
			op = "begin"
		}
		if index == r.Count+1 {
			op = "finalize"
		}
		m, e := overviewwire.DecodeMessage(op, body)
		if e != nil || m.Section != r.Section || m.Sequence != r.Floor || m.GenerationID != r.Generation || m.ManifestHash != r.ManifestHash {
			return nil, ErrCorrupt
		}
		// Raw payload budgeting must not be evaded by outer-envelope padding.
		var envelope struct {
			Payload json.RawMessage `json:"payload"`
		}
		if json.Unmarshal(body, &envelope) != nil {
			return nil, ErrCorrupt
		}
		if op != "finalize" {
			if len(envelope.Payload) > MaxRawBytes-total {
				return nil, ErrCorrupt
			}
			total += len(envelope.Payload)
		}
		if op == "begin" {
			if m.Manifest == nil || m.Manifest.ChunkCount != r.Count || m.Manifest.CollectedAt.Format("2006-01-02T15:04:05.999999999Z07:00") != r.AttemptedAt {
				return nil, ErrCorrupt
			}
			validator, e = overviewgeneration.NewValidator(ctx, *m.Manifest)
			if e != nil {
				return nil, ErrCorrupt
			}
		} else if op == "append" {
			if m.Chunk == nil || validator.Add(*m.Chunk) != nil {
				return nil, ErrCorrupt
			}
		}
		p.frames = append(p.frames, body)
	}
	if len(rest) != 0 || validator == nil {
		return nil, ErrCorrupt
	}
	if _, e := validator.Finish(); e != nil {
		return nil, ErrCorrupt
	}
	if r.Last != nil && r.Last.Sequence == r.Floor && r.Next > 0 && r.Last.Operation != "abort" {
		index := r.Next - 1
		if int(index) >= len(p.frames) || digest(p.frames[index]) != r.Last.Digest {
			return nil, ErrCorrupt
		}
		receipt, e := overviewwire.DecodeReceipt(r.Last.Receipt, r.Last.Operation, p.frames[index])
		if e != nil || !receiptContext(r, receipt) {
			return nil, ErrCorrupt
		}
	}
	return p, nil
}
