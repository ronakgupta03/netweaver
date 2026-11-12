// internal/telemetry/format.go
package telemetry

import "fmt"

var units = []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}

// FormatBytes renders a byte count with a binary unit suffix.
func FormatBytes(v uint64) string {
	f := float64(v)
	idx := 0
	for f >= 1024 && idx < len(units)-1 {
		f /= 1024
		idx++
	}
	if idx == 0 {
		return fmt.Sprintf("%d B", v)
	}
	if f >= 100 {
		return fmt.Sprintf("%.0f %s", f, units[idx])
	}
	return fmt.Sprintf("%.1f %s", f, units[idx])
}

// FormatRate renders a bytes-per-second rate with a binary unit suffix.
func FormatRate(v float64) string {
	if v <= 0 {
		return "0 B/s"
	}
	f := v
	idx := 0
	for f >= 1024 && idx < len(units)-1 {
		f /= 1024
		idx++
	}
	if f >= 100 {
		return fmt.Sprintf("%.0f %s/s", f, units[idx])
	}
	return fmt.Sprintf("%.1f %s/s", f, units[idx])
}
