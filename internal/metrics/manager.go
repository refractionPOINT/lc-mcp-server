package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	monitoring "cloud.google.com/go/monitoring/apiv3/v2"
	"cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	"google.golang.org/genproto/googleapis/api/metric"
	"google.golang.org/genproto/googleapis/api/monitoredres"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/refractionpoint/lc-mcp-go/internal/auth"
)

const (
	// Metric type prefix for custom metrics
	metricTypePrefix = "custom.googleapis.com/mcp_server"
)

// Manager handles GCP metrics reporting
type Manager struct {
	config      *Config
	client      *monitoring.MetricClient
	projectPath string
	logger      *slog.Logger
	instanceID  string

	// isEnabled tracks whether metrics should be recorded (separate from client existence)
	// This allows tracking metrics in memory even if GCP client fails to initialize
	isEnabled bool

	// In-memory tracking
	mu             sync.RWMutex
	uniqueUsers    map[string]struct{}
	oauthUsers     map[string]struct{}
	nonOAuthUsers  map[string]struct{}
	operationCount int64
	startTime      time.Time

	// Background reporter
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewManager creates a new metrics manager
// If metrics are disabled or initialization fails, returns a no-op manager
func NewManager(ctx context.Context, config *Config, logger *slog.Logger) (*Manager, error) {
	m := &Manager{
		config:        config,
		logger:        logger,
		uniqueUsers:   make(map[string]struct{}),
		oauthUsers:    make(map[string]struct{}),
		nonOAuthUsers: make(map[string]struct{}),
		startTime:     time.Now(),
		stopCh:        make(chan struct{}),
	}

	// If disabled, return no-op manager
	if !config.Enabled {
		logger.Info("GCP metrics reporting disabled")
		return m, nil
	}

	// Get instance ID for metric labels
	m.instanceID = getInstanceID()

	// Create GCP Monitoring client
	client, err := monitoring.NewMetricClient(ctx)
	if err != nil {
		logger.Warn("Failed to create GCP Monitoring client, metrics will be disabled",
			"error", err)
		return m, nil // Return no-op manager instead of error
	}
	m.client = client

	// Determine project ID
	projectID := config.ProjectID
	if projectID == "" {
		// Try to auto-detect from environment or metadata server
		projectID = detectProjectID()
		if projectID == "" {
			logger.Warn("Could not detect GCP project ID, metrics will be disabled")
			client.Close()
			m.client = nil
			return m, nil
		}
	}
	m.projectPath = fmt.Sprintf("projects/%s", projectID)
	m.isEnabled = true // Metrics tracking is now active

	logger.Info("GCP metrics reporting enabled",
		"project", projectID,
		"report_interval", config.ReportInterval,
		"instance_id", m.instanceID)

	// Start background reporter with a fresh context (not tied to init context)
	// The reporter has its own lifecycle controlled by stopCh
	m.wg.Add(1)
	go m.reportLoop()

	return m, nil
}

// RecordOperation records a tool operation with its auth context
func (m *Manager) RecordOperation(authCtx *auth.AuthContext) {
	if !m.isEnabled || authCtx == nil {
		return // No-op if disabled or no auth context
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Increment operation count
	m.operationCount++

	// Get user identifier based on auth mode
	userID := m.getUserIdentifier(authCtx)
	m.uniqueUsers[userID] = struct{}{}

	// Track by auth type
	switch authCtx.Mode {
	case auth.AuthModeUIDOAuth:
		if authCtx.UID != "" {
			m.oauthUsers[authCtx.UID] = struct{}{}
		}
	case auth.AuthModeUIDKey:
		if authCtx.UID != "" {
			m.nonOAuthUsers["uid:"+authCtx.UID] = struct{}{}
		}
	case auth.AuthModeNormal:
		if authCtx.OID != "" {
			m.nonOAuthUsers["oid:"+authCtx.OID] = struct{}{}
		}
	}
}

// getUserIdentifier returns a unique identifier for the user based on auth mode
func (m *Manager) getUserIdentifier(authCtx *auth.AuthContext) string {
	// Use UID for user modes, OID for org mode
	if authCtx.UID != "" {
		return "uid:" + authCtx.UID
	}
	if authCtx.OID != "" {
		return "oid:" + authCtx.OID
	}
	return "unknown"
}

// Close stops the background reporter and closes the client
func (m *Manager) Close() error {
	if m.client == nil {
		return nil
	}

	// Stop the reporter goroutine
	close(m.stopCh)
	m.wg.Wait()

	// Close the client
	return m.client.Close()
}

// reportLoop runs the periodic metric reporting
func (m *Manager) reportLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.ReportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			// Final report before shutdown
			m.report()
			return
		case <-ticker.C:
			m.report()
		}
	}
}

// report sends current metrics to GCP Monitoring
func (m *Manager) report() {
	if m.client == nil {
		return
	}

	// Use timeout to prevent blocking
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get current metric values
	m.mu.RLock()
	uniqueUsersCount := int64(len(m.uniqueUsers))
	oauthUsersCount := int64(len(m.oauthUsers))
	nonOAuthUsersCount := int64(len(m.nonOAuthUsers))
	operationCount := m.operationCount
	m.mu.RUnlock()

	now := time.Now()
	startTime := m.startTime

	// Create time series for each metric
	timeSeries := []*monitoringpb.TimeSeries{
		m.createGaugeTimeSeries("unique_users", uniqueUsersCount, now),
		m.createGaugeTimeSeries("oauth_users", oauthUsersCount, now),
		m.createGaugeTimeSeries("non_oauth_users", nonOAuthUsersCount, now),
		m.createCumulativeTimeSeries("operations", operationCount, startTime, now),
	}

	// Send to GCP
	err := m.client.CreateTimeSeries(ctx, &monitoringpb.CreateTimeSeriesRequest{
		Name:       m.projectPath,
		TimeSeries: timeSeries,
	})
	if err != nil {
		m.logger.Warn("Failed to report metrics to GCP Monitoring",
			"error", err,
			"unique_users", uniqueUsersCount,
			"operations", operationCount)
		return
	}

	m.logger.Debug("Reported metrics to GCP Monitoring",
		"unique_users", uniqueUsersCount,
		"oauth_users", oauthUsersCount,
		"non_oauth_users", nonOAuthUsersCount,
		"operations", operationCount)
}

// createGaugeTimeSeries creates a gauge time series for a metric
func (m *Manager) createGaugeTimeSeries(metricName string, value int64, endTime time.Time) *monitoringpb.TimeSeries {
	return &monitoringpb.TimeSeries{
		Metric: &metric.Metric{
			Type: fmt.Sprintf("%s/%s", metricTypePrefix, metricName),
			Labels: map[string]string{
				"instance_id": m.instanceID,
			},
		},
		Resource: &monitoredres.MonitoredResource{
			Type: "global",
			Labels: map[string]string{
				"project_id": extractProjectID(m.projectPath),
			},
		},
		MetricKind: metric.MetricDescriptor_GAUGE,
		ValueType:  metric.MetricDescriptor_INT64,
		Points: []*monitoringpb.Point{
			{
				Interval: &monitoringpb.TimeInterval{
					EndTime: timestamppb.New(endTime),
				},
				Value: &monitoringpb.TypedValue{
					Value: &monitoringpb.TypedValue_Int64Value{
						Int64Value: value,
					},
				},
			},
		},
	}
}

// createCumulativeTimeSeries creates a cumulative time series for a counter metric
func (m *Manager) createCumulativeTimeSeries(metricName string, value int64, startTime, endTime time.Time) *monitoringpb.TimeSeries {
	return &monitoringpb.TimeSeries{
		Metric: &metric.Metric{
			Type: fmt.Sprintf("%s/%s", metricTypePrefix, metricName),
			Labels: map[string]string{
				"instance_id": m.instanceID,
			},
		},
		Resource: &monitoredres.MonitoredResource{
			Type: "global",
			Labels: map[string]string{
				"project_id": extractProjectID(m.projectPath),
			},
		},
		MetricKind: metric.MetricDescriptor_CUMULATIVE,
		ValueType:  metric.MetricDescriptor_INT64,
		Points: []*monitoringpb.Point{
			{
				Interval: &monitoringpb.TimeInterval{
					StartTime: timestamppb.New(startTime),
					EndTime:   timestamppb.New(endTime),
				},
				Value: &monitoringpb.TypedValue{
					Value: &monitoringpb.TypedValue_Int64Value{
						Int64Value: value,
					},
				},
			},
		},
	}
}

// detectProjectID attempts to detect the GCP project ID from environment
func detectProjectID() string {
	// Try common environment variables
	// GOOGLE_CLOUD_PROJECT is set by Cloud Run and other GCP services
	if id := os.Getenv("GOOGLE_CLOUD_PROJECT"); id != "" {
		return id
	}
	if id := os.Getenv("GCLOUD_PROJECT"); id != "" {
		return id
	}
	if id := os.Getenv("GCP_PROJECT"); id != "" {
		return id
	}
	return ""
}

// getInstanceID returns a unique instance identifier for metric labels
func getInstanceID() string {
	// Try Cloud Run revision
	if rev := os.Getenv("K_REVISION"); rev != "" {
		return rev
	}
	// Try container instance ID
	if instance := os.Getenv("INSTANCE_ID"); instance != "" {
		return instance
	}
	// Fall back to hostname
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}

// extractProjectID extracts the project ID from a project path
func extractProjectID(projectPath string) string {
	// projectPath is "projects/PROJECT_ID"
	if len(projectPath) > 9 {
		return projectPath[9:]
	}
	return ""
}
