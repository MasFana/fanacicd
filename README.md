# Fana CI/CD Dashboard

A lightweight, self-hosted CI/CD dashboard written in Go for managing deployment pipelines with a beautiful dark-themed interface.

## Features

- 🚀 **Simple Setup** - Easy to deploy and configure
- 🎨 **Modern Dark UI** - Glass-morphism design with Tailwind CSS
- 🔄 **Auto Build & Deploy** - Automatic cloning, building, and running of projects
- 🔔 **Real-time Updates** - Server-Sent Events (SSE) for live status updates
- 🔐 **Secure Authentication** - Password-protected with session management
- 📱 **Responsive Design** - Works on desktop and mobile devices
- 🔧 **Multiple Architectures** - Supports 64-bit, 32-bit, ARM, and x86
- ⚡ **Auto-Restart** - Automatic process restart on failure
- 🔄 **Auto-Pull** - Scheduled repository updates with change detection
- 📊 **Live Logs** - Real-time build and run logs with tabbed interface
- 🗑️ **Safe Project Management** - Proper process cleanup and directory management

## Quick Start

### Prerequisites

- Go 1.21 or later
- Git
- Basic terminal access

### Installation

1. **Download the latest release:**
   ```bash
   # For Linux 64-bit
   wget https://github.com/MasFana/fanacicd/releases/latest/download/fanacicd-linux-amd64
   chmod +x fanacicd-linux-amd64
   ./fanacicd-linux-amd64
   ```

2. **Or build from source:**
   ```bash
   git clone https://github.com/MasFana/fanacicd.git
   cd fanacicd
   go build -o fanacicd main.go
   ./fanacicd
   ```

3. **Access the dashboard:**
   - Open http://localhost:8080
   - Default password: `admin12345`

### Environment Variables

- `PORT` - Server port (default: 8080)
- `CI_DASHBOARD_PASSWORD` - Dashboard password
- `CI_DASHBOARD_COOKIE_SECURE` - Set to "true" for HTTPS

## Download

### Latest Releases

Visit the [Releases Page](https://github.com/MasFana/fanacicd/releases) to download pre-built binaries for your platform:

| Platform | Architecture | File |
|----------|--------------|------|
| Linux | 64-bit | `fanacicd-linux-amd64` |
| Linux | 32-bit | `fanacicd-linux-386` |
| Linux | ARM64 | `fanacicd-linux-arm64` |
| Linux | ARM | `fanacicd-linux-arm` |
| Windows | 64-bit | `fanacicd-windows-amd64.exe` |
| Windows | 32-bit | `fanacicd-windows-386.exe` |
| macOS | 64-bit | `fanacicd-darwin-amd64` |
| macOS | ARM64 | `fanacicd-darwin-arm64` |

### Verification

All releases are automatically built using GitHub Actions. You can verify the build process in the `.github/workflows/release.yml` file.

## Usage

### Adding a Project

1. Click "Add New Project" in the dashboard
2. Fill in project details:
   - **Project Name**: Your project identifier
   - **Repository URL**: Git repository URL
   - **Branch**: Git branch (default: main)
   - **Build Command**: Commands to build your project
   - **Run Command**: Command to run your application
   - **Auto Pull**: Enable automatic repository updates
   - **Auto Restart**: Enable automatic process restart

### Project Actions

- **Build**: Manually trigger build process
- **Run/Stop**: Start or stop the application
- **Pull**: Fetch latest changes from repository
- **Logs**: View build and runtime logs
- **Edit**: Modify project configuration
- **Delete**: Remove project and clean up

### Auto Features

- **Auto Clone**: New projects are automatically cloned
- **Auto Build**: Projects build automatically after cloning
- **Auto Run**: Projects start automatically after successful build
- **Auto Pull**: Scheduled repository updates (configurable interval)
- **Auto Restart**: Automatic restart on process exit

## GitHub Actions

This project includes GitHub Actions for automatic multi-architecture builds:

```yaml
name: Release

on:
  push:
    tags: ['v*']
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - os: linux
            arch: amd64
          - os: linux
            arch: 386
          - os: linux
            arch: arm64
          - os: linux
            arch: arm
          - os: windows
            arch: amd64
          - os: windows
            arch: 386
          - os: darwin
            arch: amd64
          - os: darwin
            arch: arm64
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
          
      - name: Build
        run: |
          GOOS=${{ matrix.os }} GOARCH=${{ matrix.arch }} go build -o fanacicd-${{ matrix.os }}-${{ matrix.arch }}${{ matrix.ext }} main.go
        env:
          EXT: ${{ matrix.os == 'windows' && '.exe' || '' }}
          
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: fanacicd-${{ matrix.os }}-${{ matrix.arch }}
          path: fanacicd-${{ matrix.os }}-${{ matrix.arch }}${{ matrix.ext }}
```

## Configuration

### Password Management

Change the default password by editing `db.json`:

```json
{
  "password": "your-new-secure-password",
  "projects": {}
}
```

Or set the `CI_DASHBOARD_PASSWORD` environment variable.

### Project Directory

Projects are stored in the `projects/` directory relative to the binary:

```
projects/
├── project-123456789/
│   ├── src/
│   ├── build artifacts
│   └── runtime files
└── project-987654321/
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard UI |
| `/api/login` | POST | User authentication |
| `/api/logout` | POST | User logout |
| `/api/projects` | GET/POST | List/Create projects |
| `/api/projects/{id}` | GET/PUT/DELETE | Get/Update/Delete project |
| `/api/build/{id}` | POST | Trigger build |
| `/api/run/{id}` | POST | Start application |
| `/api/stop/{id}` | POST | Stop application |
| `/api/pull/{id}` | POST | Pull repository updates |
| `/api/logs/{id}` | GET | Get project logs |
| `/api/events` | GET | SSE for real-time updates |

## Security

- Password authentication with secure session management
- Environment variable for password configuration
- Secure cookie settings for production
- CORS protection for API endpoints
- Input validation and sanitization

## Development

### Building from Source

```bash
git clone https://github.com/MasFana/fanacicd.git
cd fanacicd
go build -o fanacicd main.go
```

### Running Tests

```bash
go test ./...
```

### Code Structure

```
fanacicd/
├── main.go                 # Main application entry point
├── dashboard.html         # Embedded dashboard UI
├── login.html            # Embedded login page
├── go.mod                # Go module definition
├── db.json               # Configuration and projects database
└── projects/             # Project directories (created automatically)
```

## Troubleshooting

### Common Issues

1. **Port already in use**
   - Change the `PORT` environment variable

2. **Permission denied**
   - Ensure write permissions in the current directory
   - The application needs to create `db.json` and `projects/` directory

3. **Git clone failures**
   - Verify repository URLs are accessible
   - Check network connectivity
   - Ensure Git is installed on the system

4. **Process not starting**
   - Verify run commands are correct
   - Check project-specific dependencies
   - Review logs for error messages

### Logs

Application logs are printed to stdout. Check the console output for detailed error information and debugging.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- Create an [Issue](https://github.com/MasFana/fanacicd/issues) for bug reports
- Check [Releases](https://github.com/MasFana/fanacicd/releases) for updates
- Review closed issues for common solutions

---

**Note**: Always change the default password in production environments and ensure proper security measures are in place for your deployment.