package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type SessionRecord struct {
	SessionID       string    `json:"session_id"`
	SignalingURL    string    `json:"signaling_url"`
	ControllerToken string    `json:"controller_token,omitempty"`
	PairedAt        time.Time `json:"paired_at"`
	LastSeen        time.Time `json:"last_seen"`
}

func SaveSession(vaultDir string, rec SessionRecord) error {
	dir := filepath.Join(vaultDir, "sessions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, rec.SessionID+".json"), b, 0o600)
}

func LoadSession(vaultDir, id string) (*SessionRecord, error) {
	b, err := os.ReadFile(filepath.Join(vaultDir, "sessions", id+".json"))
	if err != nil {
		return nil, err
	}
	var rec SessionRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func ListSessions(vaultDir string) ([]SessionRecord, error) {
	dir := filepath.Join(vaultDir, "sessions")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]SessionRecord, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		rec, err := LoadSession(vaultDir, e.Name()[:len(e.Name())-len(filepath.Ext(e.Name()))])
		if err == nil {
			out = append(out, *rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SessionID < out[j].SessionID })
	return out, nil
}
