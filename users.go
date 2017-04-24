package auth

import (
	"encoding/csv"
	"os"
	"sync"
)

// SecretProvider is used by authenticators. Takes user name and realm
// as an argument, returns secret required for authentication (HA1 for
// digest authentication, properly encrypted password for basic).
//
// Returning an empty string means failing the authentication.
type SecretProvider func(user, realm string) string

// File Common functions for file auto-reloading
type File struct {
	Path string
	Info os.FileInfo
	/* must be set in inherited types during initialization */
	Reload func()
	mu     sync.Mutex
}

// ReloadIfNeeded reload if needed
func (f *File) ReloadIfNeeded() {
	info, err := os.Stat(f.Path)
	if err != nil {
		panic(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Info == nil || f.Info.ModTime() != info.ModTime() {
		f.Info = info
		f.Reload()
	}
}

// HtdigestFile Structure used for htdigest file authentication. Users map realms to
// maps of users to their HA1 digests.
//
type HtdigestFile struct {
	File
	Users map[string]map[string]string
	mu    sync.RWMutex
}

func reloadHtdigest(hf *HtdigestFile) {
	r, err := os.Open(hf.Path)
	if err != nil {
		panic(err)
	}
	csvReader := csv.NewReader(r)
	csvReader.Comma = ':'
	csvReader.Comment = '#'
	csvReader.TrimLeadingSpace = true

	records, err := csvReader.ReadAll()
	if err != nil {
		panic(err)
	}

	hf.mu.Lock()
	defer hf.mu.Unlock()
	hf.Users = make(map[string]map[string]string)
	for _, record := range records {
		_, exists := hf.Users[record[1]]
		if !exists {
			hf.Users[record[1]] = make(map[string]string)
		}
		hf.Users[record[1]][record[0]] = record[2]
	}
}

// HtdigestFileProvider SecretProvider implementation based on htdigest-formated files. Will
//reload htdigest file on changes. Will panic on syntax errors in
//htdigest files.
//
func HtdigestFileProvider(filename string) SecretProvider {
	hf := &HtdigestFile{File: File{Path: filename}}
	hf.Reload = func() { reloadHtdigest(hf) }
	return func(user, realm string) string {
		hf.ReloadIfNeeded()
		hf.mu.RLock()
		defer hf.mu.RUnlock()
		_, exists := hf.Users[realm]
		if !exists {
			return ""
		}
		digest, exists := hf.Users[realm][user]
		if !exists {
			return ""
		}
		return digest
	}
}

/*HtpasswdFile Structure used for htdigest file authentication. Users map users to
their salted encrypted password
*/
type HtpasswdFile struct {
	File
	Users map[string]string
	mu    sync.RWMutex
}

func reloadHtpasswd(h *HtpasswdFile) {
	r, err := os.Open(h.Path)
	if err != nil {
		panic(err)
	}
	csvReader := csv.NewReader(r)
	csvReader.Comma = ':'
	csvReader.Comment = '#'
	csvReader.TrimLeadingSpace = true

	records, err := csvReader.ReadAll()
	if err != nil {
		panic(err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.Users = make(map[string]string)
	for _, record := range records {
		h.Users[record[0]] = record[1]
	}
}

// HtpasswdFileProvider SecretProvider implementation based on htpasswd-formated files. Will
// reload htpasswd file on changes. Will panic on syntax errors in
// htpasswd files. Realm argument of the SecretProvider is ignored.
//
func HtpasswdFileProvider(filename string) SecretProvider {
	h := &HtpasswdFile{File: File{Path: filename}}
	h.Reload = func() { reloadHtpasswd(h) }
	return func(user, realm string) string {
		h.ReloadIfNeeded()
		h.mu.RLock()
		password, exists := h.Users[user]
		h.mu.RUnlock()
		if !exists {
			return ""
		}
		return password
	}
}
