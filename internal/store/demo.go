package store

import "errors"

// RequireSyntheticDemo inspects all rows rather than the bounded UI lists. It
// is read-only and must run before seeding an existing demo-only database.
func (s *Store) RequireSyntheticDemo() error {
	var mixed int
	err := s.db.QueryRow(`SELECT
		EXISTS(SELECT 1 FROM devices WHERE json_type(body,'$.synthetic') IS NOT 'true' OR json_extract(body,'$.source') IS NOT 'synthetic')
		OR EXISTS(SELECT 1 FROM cases WHERE json_type(body,'$.synthetic') IS NOT 'true')`).Scan(&mixed)
	if err != nil {
		return err
	}
	if mixed != 0 {
		return errors.New("demo-only requires synthetic state; choose a fresh --db path")
	}
	return nil
}
