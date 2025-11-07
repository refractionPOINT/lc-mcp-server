package historical

import (
	"testing"
)

func TestParseTimeframe(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		wantHas       bool
		wantDays      float64
		wantErr       bool
	}{
		{
			name:     "No timeframe",
			query:    "plat == windows | * | event/* contains 'psexec'",
			wantHas:  false,
			wantDays: 0,
			wantErr:  false,
		},
		{
			name:     "30 days",
			query:    "-30d | plat == windows | * | event/* contains 'psexec'",
			wantHas:  true,
			wantDays: 30,
			wantErr:  false,
		},
		{
			name:     "7 days",
			query:    "-7d | plat == windows | * | event/* contains 'psexec'",
			wantHas:  true,
			wantDays: 7,
			wantErr:  false,
		},
		{
			name:     "24 hours",
			query:    "-24h | plat == windows | * | event/* contains 'psexec'",
			wantHas:  true,
			wantDays: 1,
			wantErr:  false,
		},
		{
			name:     "48 hours",
			query:    "-48h | plat == windows | * | event/* contains 'psexec'",
			wantHas:  true,
			wantDays: 2,
			wantErr:  false,
		},
		{
			name:     "30 minutes",
			query:    "-30m | plat == windows | * | event/* contains 'psexec'",
			wantHas:  true,
			wantDays: 30.0 / (60 * 24), // 0.0208333...
			wantErr:  false,
		},
		{
			name:     "60 days",
			query:    "-60d | plat == windows | * | event/* contains 'psexec'",
			wantHas:  true,
			wantDays: 60,
			wantErr:  false,
		},
		{
			name:     "Timeframe without pipe",
			query:    "-7d plat == windows | * | event/* contains 'psexec'",
			wantHas:  true,
			wantDays: 7,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHas, gotDays, err := parseTimeframe(tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTimeframe() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotHas != tt.wantHas {
				t.Errorf("parseTimeframe() gotHas = %v, want %v", gotHas, tt.wantHas)
			}
			// For days comparison, use a small epsilon for floating point comparison
			epsilon := 0.0001
			if gotHas && !floatEquals(gotDays, tt.wantDays, epsilon) {
				t.Errorf("parseTimeframe() gotDays = %v, want %v", gotDays, tt.wantDays)
			}
		})
	}
}

func TestValidateAndPrepareQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		want    string
		wantErr bool
	}{
		{
			name:    "No timeframe - adds -30d",
			query:   "plat == windows | * | event/* contains 'psexec'",
			want:    "-30d | plat == windows | * | event/* contains 'psexec'",
			wantErr: false,
		},
		{
			name:    "7 days - allowed",
			query:   "-7d | plat == windows | * | event/* contains 'psexec'",
			want:    "-7d | plat == windows | * | event/* contains 'psexec'",
			wantErr: false,
		},
		{
			name:    "30 days - allowed",
			query:   "-30d | plat == windows | * | event/* contains 'psexec'",
			want:    "-30d | plat == windows | * | event/* contains 'psexec'",
			wantErr: false,
		},
		{
			name:    "24 hours - allowed",
			query:   "-24h | plat == windows | * | event/* contains 'psexec'",
			want:    "-24h | plat == windows | * | event/* contains 'psexec'",
			wantErr: false,
		},
		{
			name:    "60 days - rejected",
			query:   "-60d | plat == windows | * | event/* contains 'psexec'",
			want:    "",
			wantErr: true,
		},
		{
			name:    "31 days - rejected",
			query:   "-31d | plat == windows | * | event/* contains 'psexec'",
			want:    "",
			wantErr: true,
		},
		{
			name:    "720 hours (30 days) - allowed",
			query:   "-720h | plat == windows | * | event/* contains 'psexec'",
			want:    "-720h | plat == windows | * | event/* contains 'psexec'",
			wantErr: false,
		},
		{
			name:    "721 hours (>30 days) - rejected",
			query:   "-721h | plat == windows | * | event/* contains 'psexec'",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateAndPrepareQuery(tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAndPrepareQuery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("validateAndPrepareQuery() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper function for floating point comparison
func floatEquals(a, b, epsilon float64) bool {
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return diff < epsilon
}
