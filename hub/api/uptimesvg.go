package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/mwgg/libreping/hub/store"
)

// An embeddable shields.io-style uptime badge for a single check, so a monitored
// service's availability can be dropped into a README or status page with a plain
// <img>. Like the network banner, ONLY integers, a fixed label set, and a
// formatted percentage number are ever drawn — the check_id is used solely to look
// up local data and is never rendered — so there is nothing attacker-controllable
// to escape.

// Badge colors by availability threshold (right-hand value region).
const (
	badgeGreen = "#15803d" // up green, ≥ 99.9%
	badgeAmber = "#b45309" // amber, ≥ 99%
	badgeRed   = "#b91c1c" // red, below 99%
	badgeGrey  = "#6b7280" // grey, no data / not held
	badgeLeft  = "#54584e" // neutral label region (svgInk2)
	badgeText  = "#ffffff"
)

// badgeWindowLabels maps each known uptime window to the fixed text drawn on the
// badge's left label. Because the window is validated against this exact set, the
// label is always one of these constant strings — never caller input.
var badgeWindowLabels = map[string]string{
	"24h": "uptime 24h",
	"7d":  "uptime 7d",
	"30d": "uptime 30d",
}

func (s *Server) handleUptimeBadgeSVG(w http.ResponseWriter, r *http.Request) {
	checkID := r.URL.Query().Get("check_id")
	if checkID == "" || len(checkID) > maxCheckIDLen {
		http.Error(w, "check_id is required", http.StatusBadRequest)
		return
	}
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "30d"
	}
	label, ok := badgeWindowLabels[window]
	if !ok {
		http.Error(w, "window must be one of 24h, 7d, 30d", http.StatusBadRequest)
		return
	}

	// A hub that doesn't hold this check's shard has no local data; render an "n/a"
	// badge rather than reaching across the mesh (mirrors handleUptime).
	value, color := "n/a", badgeGrey
	if s.interest.Holds(checkID) {
		maint, err := s.maint.IntervalsForCheck(r.Context(), checkID)
		if err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		rep, err := store.ComputeUptime(r.Context(), s.store, checkID, s.now().UnixMilli(), maint)
		if err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		if uw := rep.Windows[window]; uw.Available && uw.Uptime != nil {
			value, color = formatUptimePct(*uw.Uptime), badgeColor(*uw.Uptime)
		}
	}

	writeSVG(w, renderBadgeSVG(label, value, color))
}

// badgeColor picks the value-region color from a fractional uptime (0..1):
// green ≥99.9%, amber ≥99%, red below.
func badgeColor(uptime float64) string {
	switch pct := uptime * 100; {
	case pct >= 99.9:
		return badgeGreen
	case pct >= 99:
		return badgeAmber
	default:
		return badgeRed
	}
}

// formatUptimePct renders a fractional uptime (0..1) as a one-decimal percentage
// string, e.g. 0.9985 → "99.9%". Only digits, a dot and a percent sign result, so
// the output is safe to embed directly in the SVG.
func formatUptimePct(uptime float64) string {
	return strconv.FormatFloat(uptime*100, 'f', 1, 64) + "%"
}

// renderBadgeSVG builds a flat two-region badge: a neutral left label and a
// color-coded right value. Region widths are derived from the character count so
// the text is never clipped; label and value are both drawn from a fixed set /
// formatted number, so nothing untrusted reaches the markup.
func renderBadgeSVG(label, value, color string) string {
	const (
		h      = 20 // badge height
		charW  = 7  // approximate glyph advance at font-size 11
		padX   = 6  // horizontal padding either side of each region's text
		fontSz = 11
	)
	labelW := 2*padX + charW*len([]rune(label))
	valueW := 2*padX + charW*len([]rune(value))
	total := labelW + valueW

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="%s: %s" font-family="system-ui,Verdana,sans-serif">`,
		total, h, total, h, label, value)
	// Two solid regions with rounded outer corners (flat-square style). The label
	// fills the whole rounded background; the value region sits on top, and a thin
	// square-edged rect overpaints its rounded left corners so the seam is flush.
	fmt.Fprintf(&b, `<rect width="%d" height="%d" rx="3" fill="%s"/>`, total, h, badgeLeft)
	fmt.Fprintf(&b, `<rect x="%d" width="%d" height="%d" rx="3" fill="%s"/>`, labelW, valueW, h, color)
	fmt.Fprintf(&b, `<rect x="%d" width="3" height="%d" fill="%s"/>`, labelW, h, color)
	// Centered text in each region.
	fmt.Fprintf(&b, `<text x="%d" y="14" fill="%s" font-size="%d" text-anchor="middle">%s</text>`,
		labelW/2, badgeText, fontSz, label)
	fmt.Fprintf(&b, `<text x="%d" y="14" fill="%s" font-size="%d" text-anchor="middle">%s</text>`,
		labelW+valueW/2, badgeText, fontSz, value)
	b.WriteString(`</svg>`)
	return b.String()
}
