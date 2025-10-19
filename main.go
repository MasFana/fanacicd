// file: main.go
package main

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
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
	LastBuild    string    `json:"last_build"`
	LastRun      string    `json:"last_run"`
	LastPull     time.Time `json:"last_pull"` // Changed to time.Time
	AutoPull     bool      `json:"auto_pull"`
	PullInterval int       `json:"pull_interval"`
	AutoRestart  bool      `json:"auto_restart"` // Added AutoRestart field
	Branch       string    `json:"branch"`       // Added Branch field
}

type ProjectState struct {
	Project
	BuildLog []string `json:"build_log"`
	RunLog   []string `json:"run_log"`
	mu       sync.RWMutex
	cmdMu    sync.Mutex // protects exec.Cmd lifecycle if needed
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
	go dashboard.cleanupOrphanedProcesses() // Call cleanup on startup
}

// cleanupOrphanedProcesses checks for and kills processes that were running
// when the dashboard last shut down, but are no longer managed.
func (d *Dashboard) cleanupOrphanedProcesses() {
	log.Println("Starting orphaned process cleanup...")
	d.mu.Lock()
	// No defer d.mu.Unlock() here, unlock explicitly before saveDB

	for id, state := range d.projects {
		state.mu.Lock()
		pid := state.PID
		wasRunning := state.Status == "Running" // Check if it was running before cleanup
		state.mu.Unlock()

		if pid > 0 {
			proc, err := os.FindProcess(pid)
			if err == nil && proc != nil {
				// Attempt to kill the process
				if err := proc.Kill(); err != nil {
					log.Printf("Error killing potential orphaned process %d for project %s: %v. Assuming it was already dead or inaccessible.", pid, id, err)
					// Even if killing fails, we must clear the PID and set status to Stopped
					state.mu.Lock()
					state.PID = 0
					state.Status = "Stopped"
					state.mu.Unlock()
				} else {
					log.Printf("Successfully killed orphaned process %d for project %s.", pid, id)
					_, _ = proc.Wait() // Wait for it to truly exit
					state.mu.Lock()
					state.PID = 0
					state.Status = "Stopped"
					state.mu.Unlock()
				}
			} else {
				// os.FindProcess failed, or proc was nil. Assume it's not running.
				log.Printf("Project %s: Process with PID %d not found or inaccessible. Clearing stale PID.", id, pid)
				state.mu.Lock()
				state.PID = 0
				state.Status = "Stopped"
				state.mu.Unlock()
			}
		}

		// Auto-run if it was previously running or auto-restart is enabled
		state.mu.RLock()
		autoRestart := state.AutoRestart
		state.mu.RUnlock()

		if wasRunning || autoRestart {
			log.Printf("Project %s was running or has auto-restart enabled. Attempting to restart.", id)
			go state.run()
		}
	}
	d.mu.Unlock() // Unlock before calling saveDB
	saveDB()      // Save DB after cleanup to persist status changes
	log.Println("Orphaned process cleanup finished.")
}

func getDefaultPassword() string {
	if envPass := os.Getenv("CI_DASHBOARD_PASSWORD"); envPass != "" {
		return envPass
	}
	return "admin12345"
}

// secure token generator
func (d *Dashboard) generateSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// fallback to timestamp-hex if crypto fails (very unlikely)
		return fmt.Sprintf("%x-%d", b, time.Now().UnixNano())
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

// Load DB with safe locking and copying
func loadDB() {
	data, err := os.ReadFile("db.json")
	if err != nil {
		log.Printf("No db.json found, creating default...")
		saveDB()
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
		log.Printf("Error loading db.json: %v", err)
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
				log.Printf("loadDB: Error parsing LastPull for project %s: %v. Setting to Unix epoch.", id, err)
				proj.LastPull = time.Unix(0, 0)
			} else {
				proj.LastPull = parsedTime
			}
		} else {
			proj.LastPull = time.Unix(0, 0)
		}

		dashboard.projects[id] = &ProjectState{
			Project:  proj,
			BuildLog: []string{},
			RunLog:   []string{},
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
		// copy project to avoid race and include latest fields
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

	if err := os.WriteFile("db.json", data, 0644); err != nil {
		log.Printf("Error saving db.json: %v", err)
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
	if project.LastPull.IsZero() { // Check if LastPull is zero value
		project.LastPull = time.Unix(0, 0) // Set to Unix epoch start
	}
	if project.Branch == "" {
		project.Branch = "main" // Default branch
	}
	// project.AutoRestart = false // Removed default to false, now uses value from form

	d.projects[project.ID] = &ProjectState{
		Project:  *project,
		BuildLog: []string{},
		RunLog:   []string{},
	}
	state := d.projects[project.ID] // Get the newly created project state
	d.mu.Unlock()                   // Release lock before calling saveDB
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
	state.AutoRestart = project.AutoRestart // Update AutoRestart field
	state.Branch = project.Branch           // Update Branch field
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

    // Mark as deleting to prevent new operations
    state.mu.Lock()
    state.Status = "Deleting"
    state.mu.Unlock()
    
    d.mu.Unlock() // Release dashboard lock early

    // Stop the project (non-blocking)
    state.stop()

    // Remove from projects map
    d.mu.Lock()
    delete(d.projects, id)
    d.mu.Unlock()

    // Clean up project directory in background
    go func(projectID string) {
        projectDir := filepath.Join("projects", projectID)
        if err := os.RemoveAll(projectDir); err != nil {
            log.Printf("deleteProject: Error removing project directory %s: %v", projectDir, err)
        } else {
            log.Printf("deleteProject: Project directory %s removed successfully.", projectDir)
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
	defer d.mu.RUnlock()
	projects := make([]*ProjectState, 0, len(d.projects))
	for _, p := range d.projects {
		projects = append(projects, p)
	}
	return projects
}

func (s *ProjectState) addBuildLog(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.BuildLog = append(s.BuildLog, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), line))
	if len(s.BuildLog) > 200 {
		s.BuildLog = s.BuildLog[len(s.BuildLog)-200:]
	}
}

func (s *ProjectState) addRunLog(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RunLog = append(s.RunLog, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), line))
	if len(s.RunLog) > 200 {
		s.RunLog = s.RunLog[len(s.RunLog)-200:]
	}
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
	s.LastPull = time.Now() // Set LastPull as time.Time
	s.Status = "Cloned"
	s.mu.Unlock()
	saveDB()
	return nil
}

func (s *ProjectState) pullRepo() (bool, error) { // Modified to return bool for changes
	s.mu.Lock()
	originalStatus := s.Status // Capture original status
	s.Status = "Pulling"
	s.Project.Status = "Pulling" // Update the Project struct's status
	s.mu.Unlock()
	log.Printf("Project %s: pullRepo() started. Original status: %s, New status: Pulling", s.ID, originalStatus)

	projectDir := filepath.Join("projects", s.ID)
	// if not cloned yet, clone instead
	if _, err := os.Stat(projectDir); os.IsNotExist(err) {
		cloneErr := s.cloneRepo()
		if cloneErr != nil {
			return false, cloneErr
		}
		return true, nil // Cloned, so considered new changes
	}

	cmd := exec.Command("git", "pull", "origin", s.Branch) // Pull specific branch
	cmd.Dir = projectDir
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	// Check if there were actual changes
	// A project is "up to date" if git pull output contains "Already up to date." or "up to date" (case-insensitive)
	// or if it's a fast-forward merge (which implies changes were applied).
	// We want hasChanges to be true if there were actual new commits pulled.
	hasChanges := !strings.Contains(strings.ToLower(outputStr), "already up to date.")

	// Only add logs if there are actual changes or an error
	if hasChanges || err != nil {
		s.addBuildLog("Pulling latest changes...")
		s.addBuildLog(outputStr)
	} else {
	}

	s.mu.Lock()
	if err != nil {
		s.Status = "Error"
		s.mu.Unlock()
		s.addBuildLog(fmt.Sprintf("Pull error: %v", err))
		log.Printf("Project %s: Pull failed. Status: Error", s.ID)
		return false, fmt.Errorf("pull failed: %v", err)
	}

	// If no changes, revert to original status and don't update LastPull
	if !hasChanges {
		s.Status = originalStatus // Revert to status before pull
		s.mu.Unlock()
		log.Printf("Project %s: Pull completed, no new changes. Reverting status to: %s", s.ID, originalStatus)
		saveDB() // Save to persist any other changes, but status is reverted
		return false, nil
	}

	// If there are changes, update LastPull and set status to Pulled, then check for running state
	s.LastPull = time.Now() // Set LastPull as time.Time
	if originalStatus == "Running" && s.PID > 0 {
		s.Status = "Running"
		log.Printf("Project %s: Pull completed with new changes. Restoring status to Running.", s.ID)
	} else {
		s.Status = "Pulled" // Default to Pulled if not running or original status was not Running
		log.Printf("Project %s: Pull completed with new changes. Status: Pulled", s.ID)
	}
	s.mu.Unlock()
	saveDB()
	return hasChanges, nil
}

func (s *ProjectState) build() {
	s.cmdMu.Lock()
	defer s.cmdMu.Unlock()

	s.mu.Lock()
	originalStatus := s.Status // Capture original status
	s.Status = "Building"
	s.LastBuild = time.Now().Format("2006-01-02 15:04:05")
	s.mu.Unlock()
	log.Printf("Project %s: build() started. Original status: %s, New status: Building", s.ID, originalStatus)
	// Store original status to revert to if applicable
	s.mu.Lock()
	s.Project.Status = "Building" // Update the Project struct's status
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
			log.Printf("Project %s: Build failed. Status: Build Failed", s.ID)
			saveDB()
			return
		}
	}

	s.mu.Lock()
	// After successful build, check if it was running before and restore status
	if originalStatus == "Running" && s.PID > 0 {
		s.Status = "Running"
		log.Printf("Project %s: Build completed. Restoring status to Running.", s.ID)
	} else {
		s.Status = "Built" // Default to Built if not running or original status was not Running
		log.Printf("Project %s: Build completed. Status: Built", s.ID)
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
	s.LastRun = time.Now().Format("2006-01-02 15:04:05")
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
		s.mu.Unlock()
		return
	}

	s.mu.Lock()
	if cmd.Process != nil {
		s.PID = cmd.Process.Pid
	}
	s.mu.Unlock()
	saveDB()

	// stream logs
	go func() {
		if stdout != nil {
			io.Copy(&logWriter{s, "run"}, stdout)
		}
	}()
	go func() {
		if stderr != nil {
			io.Copy(&logWriter{s, "run"}, stderr)
		}
	}()

	// wait and cleanup
	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		s.Status = "Stopped"
		s.PID = 0
		s.mu.Unlock()
		if err != nil {
			s.addRunLog(fmt.Sprintf("Process exited with error: %v", err))
		} else {
			s.addRunLog("Process exited")
		}
		saveDB()

		// Auto-restart logic
		s.mu.RLock()
		autoRestart := s.AutoRestart
		s.mu.RUnlock()

		if autoRestart {
			log.Printf("Project %s: Auto-restart enabled. Restarting...", s.ID)
			go s.run()
		}
	}()
}

func (s *ProjectState) stop() {
    s.mu.Lock()
    pid := s.PID
    s.mu.Unlock()

    if pid > 0 {
        go func(pid int) {
            if proc, err := os.FindProcess(pid); err == nil && proc != nil {
                _ = proc.Signal(os.Interrupt)
                
                // Simple channel for timeout instead of select with single case
                timeout := time.After(250 * time.Millisecond)
                <-timeout // Wait for timeout
                
                _ = proc.Kill()
                
                // Non-blocking wait with proper channel usage
                waitDone := make(chan error, 1)
                go func() {
                    _, err := proc.Wait()
                    waitDone <- err
                }()
                
                // Use select only when we have multiple cases
                <-time.After(2 * time.Second)
                // After 2 seconds, we give up (the wait is already in a goroutine)
            }
        }(pid)
    }

    s.mu.Lock()
    s.PID = 0
    s.Status = "Stopped"
    s.mu.Unlock()
    log.Printf("Project %s: Status set to Stopped, PID reset. Calling saveDB().", s.ID)
    saveDB()
}

type logWriter struct {
	state *ProjectState
	typ   string
}

func (lw *logWriter) Write(p []byte) (n int, err error) {
	// minimal line handling; logs are time-stamped in add*Log
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
	// session cookie preferred
	if cookie, err := r.Cookie("ci_dashboard_session"); err == nil {
		if dashboard.validateSession(cookie.Value) {
			return true
		}
	}
	// fallback to header token for programmatic calls
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
	project.mu.RLock()
	var logs []string
	if typ == "run" {
		logs = append([]string(nil), project.RunLog...)
	} else {
		logs = append([]string(nil), project.BuildLog...)
	}
	project.mu.RUnlock()
	if len(logs) > lines {
		logs = logs[len(logs)-lines:]
	}
	_ = json.NewEncoder(w).Encode(logs)
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	// allow credentials - check cookie auth
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
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		case <-r.Context().Done():
			return
		}
	}
}

// Scheduler for auto-pull uses LastPull field
func startAutoPullScheduler() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		projects := dashboard.getAllProjects()
		for _, project := range projects {
			project.mu.RLock()
			autoPull := project.AutoPull
			interval := project.PullInterval
			lastPull := project.LastPull // Now time.Time
			project.mu.RUnlock()

			if !autoPull || interval <= 0 {
				continue
			}

			timeSinceLastPull := time.Since(lastPull)
			requiredInterval := time.Duration(interval) * time.Minute

			if timeSinceLastPull > requiredInterval {
				log.Printf("Project %s: Auto-pull triggered. Time since last pull: %v, Required interval: %v", project.ID, timeSinceLastPull, requiredInterval)
				go func(p *ProjectState) {
					// Capture current status before pull
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

	log.Printf("CI/CD Dashboard starting on :%s", port)
	log.Printf("Default password: %s", dashboard.password)
	log.Printf("Edit db.json to change password")
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
