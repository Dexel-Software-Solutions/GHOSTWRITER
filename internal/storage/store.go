// Package storage provides persistent storage for GHOSTWRITER attacker profiles.
// Uses an embedded JSON file store for zero-dependency persistence.
//
// Engineer: Demiyan Dissanayake
// Organization: Dexel Software Solutions
// Contact: dexelsoftwaresolutions@gmail.com | https://github.com/Dexel-Software-Solutions
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/Dexel-Software-Solutions/ghostwriter/pkg/models"
)

// db is the in-memory representation of the persistent store.
type db struct {
	Profiles map[string]*models.AttackerProfile `json:"profiles"`
	Alerts   map[string]*models.Alert           `json:"alerts"`
}

// Store manages persistent storage of attacker profiles and alerts.
type Store struct {
	mu   sync.RWMutex
	path string
	data db
}

// Open opens (or creates) the GHOSTWRITER JSON store at the given path.
func Open(path string) (*Store, error) {
	s := &Store{
		path: path,
		data: db{
			Profiles: make(map[string]*models.AttackerProfile),
			Alerts:   make(map[string]*models.Alert),
		},
	}

	// Load existing data if file exists
	if _, err := os.Stat(path); err == nil {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open store: %w", err)
		}
		defer f.Close()
		if err := json.NewDecoder(f).Decode(&s.data); err != nil {
			return nil, fmt.Errorf("decode store: %w", err)
		}
		if s.data.Profiles == nil {
			s.data.Profiles = make(map[string]*models.AttackerProfile)
		}
		if s.data.Alerts == nil {
			s.data.Alerts = make(map[string]*models.Alert)
		}
	}

	return s, nil
}

// flush writes the in-memory store to disk. Must be called with mu held (write).
func (s *Store) flush() error {
	f, err := os.Create(s.path)
	if err != nil {
		return fmt.Errorf("create store file: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(s.data)
}

// Close flushes and closes the store.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flush()
}

// SaveProfile persists an attacker profile.
func (s *Store) SaveProfile(profile *models.AttackerProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Profiles[profile.ID] = profile
	return s.flush()
}

// GetProfile retrieves a profile by ID.
func (s *Store) GetProfile(id string) (*models.AttackerProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.data.Profiles[id]
	if !ok {
		return nil, fmt.Errorf("profile not found: %s", id)
	}
	return p, nil
}

// GetAllProfiles returns all stored profiles.
func (s *Store) GetAllProfiles() ([]*models.AttackerProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	profiles := make([]*models.AttackerProfile, 0, len(s.data.Profiles))
	for _, p := range s.data.Profiles {
		profiles = append(profiles, p)
	}
	return profiles, nil
}

// DeleteProfile removes a profile.
func (s *Store) DeleteProfile(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data.Profiles, id)
	return s.flush()
}

// SaveAlert persists a detection alert.
func (s *Store) SaveAlert(alert *models.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Alerts[alert.ID] = alert
	return s.flush()
}

// GetAllAlerts returns all stored alerts.
func (s *Store) GetAllAlerts() ([]*models.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	alerts := make([]*models.Alert, 0, len(s.data.Alerts))
	for _, a := range s.data.Alerts {
		alerts = append(alerts, a)
	}
	return alerts, nil
}

// Stats returns storage statistics.
func (s *Store) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"profiles": len(s.data.Profiles),
		"alerts":   len(s.data.Alerts),
	}
}
