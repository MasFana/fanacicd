// file: main.go
package main

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed dashboard.html
var dashboardHTML string

//go:embed login.html
var loginHTML string

type Project struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	RepoURL      string    `json:"repo_url"`
	BuildCmd     string    `json:"build_cmd"`
	RunCmd       string    `json:"run_cmd"`
	Status       string    `json:"status"`
	PID          int       `json:"pid"`
	LastBuild    time.Time `json:"last_build"`
	LastRun      time.Time `json:"last_run"`
	LastPull     time.Time `json:"last_pull"`
	AutoPull     bool      `json:"auto_pull"`
	PullInterval int       `json:"pull_interval"`
	AutoRestart  bool      `json:"auto_restart"`
	Branch       string    `json:"branch"`
}

// BoundedSlice implements a circular buffer for efficient log storage
type BoundedSlice struct {
	data  []string
	start int
	count int
	mu    sync.RWMutex
}

func NewBoundedSlice(capacity int) *BoundedSlice {
	return &BoundedSlice{
		data: make([]string, capacity),
	}
}

func (bs *BoundedSlice) Append(item string) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	
	if bs.count < len(bs.data) {
		bs.data[bs.count] = item
		bs.count++
	} else {
		bs.data[bs.start] = item
		bs.start = (bs.start + 1) % len(bs.data)
	}
}

func (bs *BoundedSlice) GetSlice() []string {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	
	if bs.count == 0 {
		return []string{}
	}
	
	if bs.count < len(bs.data) {
		result := make([]string, bs.count)
		copy(result, bs.data[:bs.count])
		return result
	}
	
	result := make([]string, len(bs.data))
	for i := 0; i < len(bs.data); i++ {
		result[i] = bs.data[(bs.start+i)%len(bs.data)]
	}
	return result
}

func (bs *BoundedSlice) GetLastN(n int) []string {
	slice := bs.GetSlice()
	if n >= len(slice) {
		return slice
	}
	return slice[len(slice)-n:]
}

func (bs *BoundedSlice) Len() int {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.count
}

type ProjectState struct {
	Project
	BuildLog *BoundedSlice `json:"-"`
	RunLog   *BoundedSlice `json:"-"`
	mu       sync.RWMutex
	cmdMu    sync.Mutex
	cmd      *exec.Cmd     // Track the command for better process management
}

type Dashboard struct {
	projects  map[string]*ProjectState
	mu        sync.RWMutex
	password  string
	sessions  map[string]time.Time
	sessionMu sync.RWMutex
}

type DB struct {
	Password string              `json:"password"`
	Projects map[string]*Project `json:"projects"`
}

var dashboard *Dashboard

func init() {
	dashboard = &Dashboard{
		projects: make(map[string]*ProjectState),
		password: getDefaultPassword(),
		sessions: make(map[string]time.Time),
	}
	loadDB()
	go dashboard.cleanupExpiredSessions()
	go dashboard.cleanupOrphanedProcesses()
}

// Improved orphaned process cleanup with better locking
func (d *Dashboard) cleanupOrphanedProcesses() {
	log.Println("Starting orphaned process cleanup...")
	
	// Get all projects without holding the lock during process operations
	d.mu.RLock()
	projects := make([]*ProjectState, 0, len(d.projects))
	for _, state := range d.projects {
		projects = append(projects, state)
	}
	d.mu.RUnlock()
	
	cleanupOccurred := false
	
	for _, state := range projects {
		state.mu.Lock()
		pid := state.PID
		wasRunning := state.Status == "Running"
		autoRestart := state.AutoRestart
		state.mu.Unlock()
		
		if pid > 0 {
			if err := state.forceKillProcess(pid); err != nil {
				log.Printf("Error killing orphaned process %d for project %s: %v", pid, state.ID, err)
			} else {
				log.Printf("Successfully cleaned up orphaned process %d for project %s", pid, state.ID)
				cleanupOccurred = true
			}
		}
		
		// Auto-run if it was previously running or auto-restart is enabled
		if wasRunning || autoRestart {
			log.Printf("Project %s was running or has auto-restart enabled. Attempting to restart.", state.ID)
			go state.run()
		}
	}
	
	if cleanupOccurred {
		saveDB()
	}
	log.Println("Orphaned process cleanup finished.")
}

// Helper method to force kill a process
func (s *ProjectState) forceKillProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		s.mu.Lock()
		s.PID = 0
		s.Status = "Stopped"
		s.mu.Unlock()
		return fmt.Errorf("process not found: %v", err)
	}
	
	// Try graceful termination first
	if err := proc.Signal(os.Interrupt); err != nil {
		log.Printf("Failed to send interrupt to process %d: %v", pid, err)
	}
	
	// Wait a bit for graceful shutdown
	time.Sleep(1 * time.Second)
	
	// Force kill if still running
	if err := proc.Kill(); err != nil {
		log.Printf("Failed to kill process %d: %v", pid, err)
	}
	
	// Wait for process to exit
	go func() {
		_, _ = proc.Wait()
	}()
	
	s.mu.Lock()
	s.PID = 0
	s.Status = "Stopped"
	s.mu.Unlock()
	
	return nil
}

func getDefaultPassword() string {
	if envPass := os.Getenv("CI_DASHBOARD_PASSWORD"); envPass != "" {
		return envPass
	}
	return "admin12345"
}

// Improved secure token generator
func (d *Dashboard) generateSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Better fallback using time and random data
		fallback := make([]byte, 16)
		binary.LittleEndian.PutUint64(fallback, uint64(time.Now().UnixNano()))
		if _, err := rand.Read(fallback[8:]); err != nil {
			// Final fallback - very unlikely
			return fmt.Sprintf("%x-%d", fallback, time.Now().UnixNano())
		}
		return hex.EncodeToString(fallback)
	}
	return hex.EncodeToString(b)
}

func (d *Dashboard) createSession() (string, time.Time) {
	token := d.generateSessionToken()
	expires := time.Now().Add(24 * time.Hour)

	d.sessionMu.Lock()
	d.sessions[token] = expires
	d.sessionMu.Unlock()

	return token, expires
}

func (d *Dashboard) validateSession(token string) bool {
	d.sessionMu.RLock()
	expires, exists := d.sessions[token]
	d.sessionMu.RUnlock()
	if !exists {
		return false
	}
	return time.Now().Before(expires)
}

func (d *Dashboard) invalidateSession(token string) {
	d.sessionMu.Lock()
	delete(d.sessions, token)
	d.sessionMu.Unlock()
}

func (d *Dashboard) cleanupExpiredSessions() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		d.sessionMu.Lock()
		for t, exp := range d.sessions {
			if now.After(exp) {
				delete(d.sessions, t)
			}
		}
		d.sessionMu.Unlock()
	}
}

// Improved DB loading with better error handling
func loadDB() {
	data, err := os.ReadFile("db.json")
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("No db.json found, creating default...")
			saveDB()
		} else {
			log.Printf("Error reading db.json: %v", err)
		}
		return
	}

	var db DB
	// Use a temporary struct to unmarshal LastPull as string for backward compatibility
	type TempProject struct {
		Project
		LastPull string `json:"last_pull"`
	}
	type TempDB struct {
		Password string                  `json:"password"`
		Projects map[string]*TempProject `json:"projects"`
	}
	var tempDb TempDB
	if err := json.Unmarshal(data, &tempDb); err != nil {
		log.Printf("Error unmarshaling db.json: %v", err)
		return
	}

	db.Password = tempDb.Password
	db.Projects = make(map[string]*Project)

	dashboard.mu.Lock()
	defer dashboard.mu.Unlock()

	if db.Password != "" {
		dashboard.password = db.Password
	}

	for id, tempProj := range tempDb.Projects {
		proj := tempProj.Project
		// Parse LastPull from string to time.Time
		if tempProj.LastPull != "" {
			parsedTime, err := time.Parse("2006-01-02 15:04:05", tempProj.LastPull)
			if err != nil {
				log.Printf("loadDB: Error parsing LastPull for project %s: %v. Setting to zero value.", id, err)
				proj.LastPull = parsedTime // Zero value
			} else {
				proj.LastPull = time.Now()
			}
		} else {
			proj.LastPull = time.Now() // Zero value
		}

		dashboard.projects[id] = &ProjectState{
			Project:  proj,
			BuildLog: NewBoundedSlice(200),
			RunLog:   NewBoundedSlice(200),
		}
	}
}

// Save DB with consistent locking and copying of project states
func saveDB() {
	db := DB{
		Password: dashboard.password,
		Projects: make(map[string]*Project),
	}

	dashboard.mu.RLock()
	for id, state := range dashboard.projects {
		state.mu.RLock()
		// Copy project to avoid race and include latest fields
		cp := state.Project
		db.Projects[id] = &cp
		state.mu.RUnlock()
	}
	dashboard.mu.RUnlock()

	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		log.Printf("Error marshaling db: %v", err)
		return
	}

	// Write to temporary file first, then rename for atomic update
	tempFile := "db.json.tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		log.Printf("Error saving db.json.tmp: %v", err)
		return
	}
	
	if err := os.Rename(tempFile, "db.json"); err != nil {
		log.Printf("Error renaming db.json.tmp to db.json: %v", err)
		// Try direct write as fallback
		if err := os.WriteFile("db.json", data, 0644); err != nil {
			log.Printf("Error saving db.json: %v", err)
		}
	}
}

func isValidProjectID(id string) bool {
	matched, _ := regexp.MatchString("^[a-zA-Z0-9_-]+$", id)
	return matched
}

func (d *Dashboard) addProject(project *Project) error {
	if project.ID != "" && !isValidProjectID(project.ID) {
		return fmt.Errorf("invalid project ID format")
	}

	d.mu.Lock()
	if project.ID == "" {
		project.ID = fmt.Sprintf("project-%d", time.Now().UnixNano())
	}

	if _, exists := d.projects[project.ID]; exists {
		d.mu.Unlock()
		return fmt.Errorf("project ID already exists")
	}

	project.Status = "Stopped"
	if project.LastPull.IsZero() {
		project.LastPull = time.Now()
	}
	if project.Branch == "" {
		project.Branch = "main"
	}

	d.projects[project.ID] = &ProjectState{
		Project:  *project,
		BuildLog: NewBoundedSlice(200),
		RunLog:   NewBoundedSlice(200),
	}
	state := d.projects[project.ID]
	d.mu.Unlock()
	saveDB()

	// Auto clone, build, and run for new projects
	go func() {
		log.Printf("New project %s added. Initiating auto clone, build, and run.", state.ID)
		if err := state.cloneRepo(); err != nil {
			state.addBuildLog(fmt.Sprintf("Auto-clone failed for new project: %v", err))
			return
		}
		state.build()
		state.run()
	}()

	return nil
}

func (d *Dashboard) updateProject(project *Project) error {
	if !isValidProjectID(project.ID) {
		return fmt.Errorf("invalid project ID format")
	}

	d.mu.RLock()
	state, exists := d.projects[project.ID]
	d.mu.RUnlock()
	if !exists {
		return fmt.Errorf("project not found")
	}

	state.mu.Lock()
	state.Name = project.Name
	state.RepoURL = project.RepoURL
	state.BuildCmd = project.BuildCmd
	state.RunCmd = project.RunCmd
	state.AutoPull = project.AutoPull
	state.PullInterval = project.PullInterval
	state.AutoRestart = project.AutoRestart
	state.Branch = project.Branch
	state.mu.Unlock()
	saveDB()
	return nil
}

func (d *Dashboard) deleteProject(id string) error {
	if !isValidProjectID(id) {
		return fmt.Errorf("invalid project ID format")
	}

	d.mu.Lock()
	state, exists := d.projects[id]
	if !exists {
		d.mu.Unlock()
		return fmt.Errorf("project not found")
	}

	// Disable auto-restart FIRST to prevent race conditions
	state.mu.Lock()
	state.AutoRestart = false
	state.Status = "Deleting"
	state.mu.Unlock()

	d.mu.Unlock()

	// Stop the project (non-blocking but with auto-restart disabled)
	state.stop()

	// Remove from projects map
	d.mu.Lock()
	delete(d.projects, id)
	d.mu.Unlock()

	// Clean up project directory in background with retry logic
	go func(projectID string) {
		projectDir := filepath.Join("projects", projectID)

		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			if err := os.RemoveAll(projectDir); err != nil {
				if i == maxRetries-1 {
					log.Printf("deleteProject: Error removing project directory %s after %d attempts: %v", projectDir, maxRetries, err)
				} else {
					time.Sleep(time.Duration(i+1) * time.Second)
					continue
				}
			} else {
				log.Printf("deleteProject: Project directory %s removed successfully.", projectDir)
				break
			}
		}
	}(id)

	saveDB()
	return nil
}

func (d *Dashboard) getProject(id string) *ProjectState {
	if !isValidProjectID(id) {
		return nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.projects[id]
}

func (d *Dashboard) getAllProjects() []*ProjectState {
	d.mu.RLock()
	projectIDs := make([]string, 0, len(d.projects))
	for id := range d.projects {
		projectIDs = append(projectIDs, id)
	}
	d.mu.RUnlock()

	projects := make([]*ProjectState, 0, len(projectIDs))
	for _, id := range projectIDs {
		if project := d.getProject(id); project != nil {
			projects = append(projects, project)
		}
	}
	return projects
}

func (s *ProjectState) addBuildLog(line string) {
	logEntry := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), line)
	s.BuildLog.Append(logEntry)
	log.Printf("BUILD [%s]: %s", s.ID, line)
}

func (s *ProjectState) addRunLog(line string) {
	logEntry := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), line)
	s.RunLog.Append(logEntry)
	log.Printf("RUN [%s]: %s", s.ID, line)
}

func (s *ProjectState) cloneRepo() error {
	s.mu.Lock()
	s.Status = "Cloning"
	s.mu.Unlock()

	projectDir := filepath.Join("projects", s.ID)
	if err := os.RemoveAll(projectDir); err != nil {
		s.addBuildLog(fmt.Sprintf("RemoveAll error: %v", err))
		return err
	}

	cmd := exec.Command("git", "clone", "--depth", "1", "--branch", s.Branch, s.RepoURL, projectDir)
	output, err := cmd.CombinedOutput()
	s.addBuildLog(fmt.Sprintf("Cloning repository %s (branch: %s)...", s.RepoURL, s.Branch))
	s.addBuildLog(string(output))

	if err != nil {
		s.mu.Lock()
		s.Status = "Error"
		s.mu.Unlock()
		s.addBuildLog(fmt.Sprintf("Clone error: %v", err))
		return fmt.Errorf("clone failed: %v", err)
	}

	s.mu.Lock()
	s.LastPull = time.Now()
	s.Status = "Cloned"
	s.mu.Unlock()
	saveDB()
	return nil
}

func (s *ProjectState) pullRepo() (bool, error) {
	s.mu.Lock()
	originalStatus := s.Status
	s.Status = "Pulling"
	s.mu.Unlock()

	projectDir := filepath.Join("projects", s.ID)
	// if not cloned yet, clone instead
	if _, err := os.Stat(projectDir); os.IsNotExist(err) {
		cloneErr := s.cloneRepo()
		if cloneErr != nil {
			return false, cloneErr
		}
		return true, nil
	}

	cmd := exec.Command("git", "pull", "origin", s.Branch)
	cmd.Dir = projectDir
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	// Check if there were actual changes
	hasChanges := !strings.Contains(strings.ToLower(outputStr), "already up to date.")

	// Only add logs if there are actual changes or an error
	if hasChanges || err != nil {
		s.addBuildLog("Pulling latest changes...")
		s.addBuildLog(outputStr)
	}

	if err != nil {
		s.mu.Lock()
		s.Status = "Error"
		s.mu.Unlock()
		s.addBuildLog(fmt.Sprintf("Pull error: %v", err))
		return false, fmt.Errorf("pull failed: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	
	// If no changes, revert to original status and don't update LastPull
	if !hasChanges {
		s.Status = originalStatus
		return false, nil
	}

	// If there are changes, update LastPull and set appropriate status
	s.LastPull = time.Now()
	if originalStatus == "Running" && s.PID > 0 {
		s.Status = "Running"
	} else {
		s.Status = "Pulled"
	}
	
	return true, nil
}

func (s *ProjectState) build() {
	s.cmdMu.Lock()
	defer s.cmdMu.Unlock()

	s.mu.Lock()
	originalStatus := s.Status
	s.Status = "Building"
	s.LastBuild = time.Now()
	s.mu.Unlock()

	projectDir := filepath.Join("projects", s.ID)
	if _, err := os.Stat(projectDir); os.IsNotExist(err) {
		if err := s.cloneRepo(); err != nil {
			s.addBuildLog(fmt.Sprintf("Clone error: %v", err))
			return
		}
	} else if err != nil {
		s.addBuildLog(fmt.Sprintf("Error checking project directory: %v", err))
		return
	}

	commands := strings.Split(s.BuildCmd, "&&")
	for _, cmdStr := range commands {
		cmdStr = strings.TrimSpace(cmdStr)
		if cmdStr == "" {
			continue
		}
		parts := strings.Fields(cmdStr)
		if len(parts) == 0 {
			continue
		}
		cmd := exec.Command(parts[0], parts[1:]...)
		cmd.Dir = projectDir
		output, err := cmd.CombinedOutput()
		s.addBuildLog(fmt.Sprintf("Running: %s", cmdStr))
		s.addBuildLog(string(output))
		if err != nil {
			s.mu.Lock()
			s.Status = "Build Failed"
			s.mu.Unlock()
			s.addBuildLog(fmt.Sprintf("Build error: %v", err))
			saveDB()
			return
		}
	}

	s.mu.Lock()
	// After successful build, check if it was running before and restore status
	if originalStatus == "Running" && s.PID > 0 {
		s.Status = "Running"
	} else {
		s.Status = "Built"
	}
	s.mu.Unlock()
	saveDB()
}

func (s *ProjectState) run() {
	s.cmdMu.Lock()
	defer s.cmdMu.Unlock()

	s.mu.Lock()
	if s.PID > 0 {
		log.Printf("Project %s: run() called but PID (%d) is already active. Aborting run.", s.ID, s.PID)
		s.mu.Unlock()
		return
	}
	s.Status = "Running"
	s.LastRun = time.Now()
	s.mu.Unlock()

	projectDir := filepath.Join("projects", s.ID)
	parts := strings.Fields(s.RunCmd)
	if len(parts) == 0 {
		s.addRunLog("Error: No run command specified")
		s.mu.Lock()
		s.Status = "Error"
		s.mu.Unlock()
		return
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Dir = projectDir

	// Store the command for better process management
	s.mu.Lock()
	s.cmd = cmd
	s.mu.Unlock()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.addRunLog(fmt.Sprintf("Error getting stdout pipe: %v", err))
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		s.addRunLog(fmt.Sprintf("Error getting stderr pipe: %v", err))
	}

	if err := cmd.Start(); err != nil {
		s.addRunLog(fmt.Sprintf("Run start error: %v", err))
		s.mu.Lock()
		s.Status = "Error"
		s.cmd = nil
		s.mu.Unlock()
		return
	}

	s.mu.Lock()
	if cmd.Process != nil {
		s.PID = cmd.Process.Pid
	}
	s.mu.Unlock()
	saveDB()

	// Stream logs with proper pipe closing
	go func() {
		defer func() {
			if stdout != nil {
				stdout.Close()
			}
		}()
		if stdout != nil {
			io.Copy(&logWriter{s, "run"}, stdout)
		}
	}()
	go func() {
		defer func() {
			if stderr != nil {
				stderr.Close()
			}
		}()
		if stderr != nil {
			io.Copy(&logWriter{s, "run"}, stderr)
		}
	}()

	// Wait and cleanup
	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		s.Status = "Stopped"
		s.PID = 0
		s.cmd = nil
		s.mu.Unlock()
		if err != nil {
			s.addRunLog(fmt.Sprintf("Process exited with error: %v", err))
		} else {
			s.addRunLog("Process exited normally")
		}
		saveDB()

		// Auto-restart logic
		s.mu.RLock()
		autoRestart := s.AutoRestart
		s.mu.RUnlock()

		if autoRestart {
			log.Printf("Project %s: Auto-restart enabled. Restarting...", s.ID)
			time.Sleep(2 * time.Second) // Brief delay before restart
			go s.run()
		}
	}()
}

func (s *ProjectState) stop() {
	s.mu.Lock()
	// Disable auto-restart temporarily during stop
	wasAutoRestart := s.AutoRestart
	s.AutoRestart = false
	pid := s.PID
	cmd := s.cmd
	s.mu.Unlock()

	if pid > 0 {
		// Try to stop using the command if available
		if cmd != nil && cmd.Process != nil {
			// Try graceful termination first
			if err := cmd.Process.Signal(os.Interrupt); err != nil {
				log.Printf("Failed to send interrupt to process %d: %v", pid, err)
			}
		} else {
			// Fallback to process lookup
			if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Signal(os.Interrupt)
			}
		}

		// Wait a bit for graceful shutdown
		time.Sleep(2 * time.Second)

		// Force kill if still running
		s.mu.Lock()
		if s.PID == pid { // Check if PID hasn't changed
			if cmd != nil && cmd.Process != nil {
				_ = cmd.Process.Kill()
			} else if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Kill()
			}
		}
		s.mu.Unlock()
	}

	s.mu.Lock()
	// Only reset if PID hasn't changed (process wasn't restarted)
	if s.PID == pid {
		s.PID = 0
		s.Status = "Stopped"
		s.cmd = nil
	}
	// Restore auto-restart setting
	s.AutoRestart = wasAutoRestart
	s.mu.Unlock()

	log.Printf("Project %s: Stop completed. AutoRestart: %v", s.ID, wasAutoRestart)
	saveDB()
}

type logWriter struct {
	state *ProjectState
	typ   string
}

func (lw *logWriter) Write(p []byte) (n int, err error) {
	line := strings.TrimSpace(string(p))
	if line != "" {
		if lw.typ == "run" {
			lw.state.addRunLog(line)
		} else {
			lw.state.addBuildLog(line)
		}
	}
	return len(p), nil
}

// Authentication and CORS

func checkAuth(w http.ResponseWriter, r *http.Request) bool {
	// Session cookie preferred
	if cookie, err := r.Cookie("ci_dashboard_session"); err == nil {
		if dashboard.validateSession(cookie.Value) {
			return true
		}
	}
	// Fallback to header token for programmatic calls
	password := r.Header.Get("X-Password")
	if subtle.ConstantTimeCompare([]byte(password), []byte(dashboard.password)) == 1 {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
	return false
}

func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "X-Password, Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) {
			return
		}
		next(w, r)
	}
}

// UI and auth handlers

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("ci_dashboard_session"); err == nil {
		if dashboard.validateSession(cookie.Value) {
			serveDashboard(w, r)
			return
		}
	}
	serveLoginPage(w, r)
}

func serveDashboard(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("dashboard").Parse(dashboardHTML)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	_ = tmpl.Execute(w, nil)
}

func serveLoginPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("login").Parse(loginHTML)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	_ = tmpl.Execute(w, nil)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var creds struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(creds.Password), []byte(dashboard.password)) != 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid password"})
		return
	}
	token, expires := dashboard.createSession()
	secureFlag := false
	if os.Getenv("CI_DASHBOARD_COOKIE_SECURE") == "true" {
		secureFlag = true
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "ci_dashboard_session",
		Value:    token,
		Expires:  expires,
		Path:     "/",
		HttpOnly: true,
		Secure:   secureFlag,
		SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("ci_dashboard_session"); err == nil {
		dashboard.invalidateSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "ci_dashboard_session",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		Path:     "/",
		HttpOnly: true,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// API handlers

func handleProjects(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		projects := dashboard.getAllProjects()
		_ = json.NewEncoder(w).Encode(projects)
	case http.MethodPost:
		var project Project
		if err := json.NewDecoder(r.Body).Decode(&project); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := dashboard.addProject(&project); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(project)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := strings.TrimPrefix(r.URL.Path, "/api/projects/")
	if !isValidProjectID(id) {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		project := dashboard.getProject(id)
		if project == nil {
			http.Error(w, "Project not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(project)
	case http.MethodPut:
		var project Project
		if err := json.NewDecoder(r.Body).Decode(&project); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		project.ID = id
		if err := dashboard.updateProject(&project); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(project)
	case http.MethodDelete:
		if err := dashboard.deleteProject(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleBuild(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/build/")
	if !isValidProjectID(id) {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}
	project := dashboard.getProject(id)
	if project == nil {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}
	go project.build()
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "build started"})
}

func handleRun(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/run/")
	if !isValidProjectID(id) {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}
	project := dashboard.getProject(id)
	if project == nil {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}
	go project.run()
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "run started"})
}

func handleStop(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/stop/")
	if !isValidProjectID(id) {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}
	project := dashboard.getProject(id)
	if project == nil {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}
	project.stop()
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "stop requested"})
}

func handlePull(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/pull/")
	if !isValidProjectID(id) {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}
	project := dashboard.getProject(id)
	if project == nil {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}
	go func() {
		if hasChanges, err := project.pullRepo(); err != nil {
			project.addBuildLog(fmt.Sprintf("Manual pull failed: %v", err))
		} else if hasChanges {
			project.addBuildLog("Manual pull completed with new changes.")
		} else {
			project.addBuildLog("Manual pull completed, no new changes.")
		}
	}()
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "pull started"})
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := strings.TrimPrefix(r.URL.Path, "/api/logs/")
	if !isValidProjectID(id) {
		http.Error(w, "Invalid project ID", http.StatusBadRequest)
		return
	}
	project := dashboard.getProject(id)
	if project == nil {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}
	typ := r.URL.Query().Get("type")
	linesStr := r.URL.Query().Get("lines")
	lines := 100
	if linesStr != "" {
		if n, err := strconv.Atoi(linesStr); err == nil && n > 0 {
			lines = n
		}
	}
	
	var logs []string
	if typ == "run" {
		logs = project.RunLog.GetLastN(lines)
	} else {
		logs = project.BuildLog.GetLastN(lines)
	}
	
	_ = json.NewEncoder(w).Encode(logs)
}

// Improved event streaming with connection management
func handleEvents(w http.ResponseWriter, r *http.Request) {
	// Allow credentials - check cookie auth
	cookie, err := r.Cookie("ci_dashboard_session")
	if err != nil || !dashboard.validateSession(cookie.Value) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Send initial state
	projects := dashboard.getAllProjects()
	if data, err := json.Marshal(projects); err == nil {
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			projects := dashboard.getAllProjects()
			if data, err := json.Marshal(projects); err == nil {
				if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
					// Client disconnected
					return
				}
				flusher.Flush()
			}
		case <-r.Context().Done():
			return
		}
	}
}

// Scheduler for auto-pull
func startAutoPullScheduler() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		projects := dashboard.getAllProjects()
		for _, project := range projects {
			project.mu.RLock()
			autoPull := project.AutoPull
			interval := project.PullInterval
			lastPull := project.LastPull
			project.mu.RUnlock()

			if !autoPull || interval <= 0 {
				continue
			}

			timeSinceLastPull := time.Since(lastPull)
			requiredInterval := time.Duration(interval) * time.Minute

			if timeSinceLastPull > requiredInterval {
				log.Printf("Project %s: Auto-pull triggered. Time since last pull: %v, Required interval: %v", project.ID, timeSinceLastPull, requiredInterval)
				go func(p *ProjectState) {
					p.mu.RLock()
					statusBeforeAutoPull := p.Status
					p.mu.RUnlock()

					hasChanges, err := p.pullRepo()
					if err != nil {
						p.addBuildLog(fmt.Sprintf("Auto-pull failed: %v", err))
						log.Printf("Project %s: Auto-pull failed: %v", p.ID, err)
						return
					}

					if hasChanges {
						p.addBuildLog("Auto-pull completed with new changes. Triggering build/run.")
						log.Printf("Project %s: Auto-pull completed with new changes. Status before auto-pull: %s. Triggering build/run.", p.ID, statusBeforeAutoPull)
						// Stop existing process if running
						p.stop()
						// Trigger build
						p.build()
						// Trigger run
						p.run()
					} else {
						p.addBuildLog("Auto-pull completed, no new changes. Skipping build/run.")
					}
				}(project)
			}
		}
	}
}

func main() {
	_ = os.MkdirAll("projects", 0755)
	go startAutoPullScheduler()

	http.HandleFunc("/", handleDashboard)
	http.HandleFunc("/api/login", enableCORS(handleLogin))
	http.HandleFunc("/api/logout", enableCORS(handleLogout))

	// Protected endpoints
	http.HandleFunc("/api/projects", enableCORS(authMiddleware(handleProjects)))
	http.HandleFunc("/api/projects/", enableCORS(authMiddleware(handleProject)))
	http.HandleFunc("/api/build/", enableCORS(authMiddleware(handleBuild)))
	http.HandleFunc("/api/run/", enableCORS(authMiddleware(handleRun)))
	http.HandleFunc("/api/stop/", enableCORS(authMiddleware(handleStop)))
	http.HandleFunc("/api/pull/", enableCORS(authMiddleware(handlePull)))
	http.HandleFunc("/api/logs/", enableCORS(authMiddleware(handleLogs)))
	// events need cookie-based auth (handled inside)
	http.HandleFunc("/api/events", handleEvents)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("CI/CD Dashboard starting on http://localhost:%s", port)
	log.Printf("Default password: %s", dashboard.password)
	log.Printf("Edit db.json to change password")
	if err := http.ListenAndServe("0.0.0.0:"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}