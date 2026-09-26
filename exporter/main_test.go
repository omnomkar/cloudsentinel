package main

import (
	"strings"
	"testing"
)

func TestSafeTarget(t *testing.T) {
	tests := []struct {
		name       string
		connString string
		want       string
	}{
		{
			name:       "url without password",
			connString: "postgresql://cloudsentinel_exporter@postgres:5432/cloudsentinel",
			want:       "host=postgres dbname=cloudsentinel",
		},
		{
			name:       "url with password",
			connString: "postgres://user:s3cret@db.internal:5432/scans?sslmode=disable",
			want:       "host=db.internal dbname=scans",
		},
		{
			name:       "keyword/value form with password",
			connString: "host=10.0.0.5 dbname=cs user=u password=s3cret",
			want:       "host=10.0.0.5 dbname=cs",
		},
		{
			name:       "unparseable",
			connString: "postgres://user:s3cret@%zz/db",
			want:       "host=? dbname=?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := safeTarget(tt.connString)
			if got != tt.want {
				t.Errorf("safeTarget(%q) = %q, want %q", tt.connString, got, tt.want)
			}
			if strings.Contains(got, "s3cret") {
				t.Errorf("safeTarget leaked the password: %q", got)
			}
		})
	}
}
