package store

import "testing"

func TestSafeClampRaisesShortRetentions(t *testing.T) {
	// Raw shorter than the hourly window and hourly shorter than the daily window
	// both risk permanent gaps, so both must be raised and warned about.
	cfg := TierConfig{
		CompressAfterDays:   2,
		RawRetentionDays:    1,
		HourlyRetentionDays: 5,
		DailyRetentionDays:  730,
	}
	got, warnings := cfg.SafeClamp()
	if got.RawRetentionDays != hourlyMaterializeWindowDays {
		t.Errorf("RawRetentionDays = %d, want %d", got.RawRetentionDays, hourlyMaterializeWindowDays)
	}
	if got.HourlyRetentionDays != dailyMaterializeWindowDays {
		t.Errorf("HourlyRetentionDays = %d, want %d", got.HourlyRetentionDays, dailyMaterializeWindowDays)
	}
	if len(warnings) != 2 {
		t.Errorf("expected 2 warnings, got %d: %v", len(warnings), warnings)
	}
	// Untouched tiers are preserved.
	if got.CompressAfterDays != 2 || got.DailyRetentionDays != 730 {
		t.Errorf("unrelated tiers modified: %+v", got)
	}
}

func TestSafeClampKeepForeverNotTripped(t *testing.T) {
	// 0 means keep-forever: it never drops rows, so it must not be clamped.
	cfg := TierConfig{RawRetentionDays: 0, HourlyRetentionDays: 0, DailyRetentionDays: 0}
	got, warnings := cfg.SafeClamp()
	if len(warnings) != 0 {
		t.Errorf("keep-forever config should not warn, got %v", warnings)
	}
	if got.RawRetentionDays != 0 || got.HourlyRetentionDays != 0 {
		t.Errorf("keep-forever retention was altered: %+v", got)
	}
}

func TestSafeClampLeavesSafeConfigAlone(t *testing.T) {
	// The default config is already safe and must pass through unchanged.
	cfg := DefaultTierConfig()
	got, warnings := cfg.SafeClamp()
	if len(warnings) != 0 {
		t.Errorf("default config should not warn, got %v", warnings)
	}
	if got != cfg {
		t.Errorf("default config was modified: %+v -> %+v", cfg, got)
	}
}
