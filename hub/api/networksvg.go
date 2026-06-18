package api

import (
	"fmt"
	"net/http"
	"strings"
)

// A static, embeddable stats banner of the live network (hubs / probes /
// countries), so the network can be dropped into a README or web page with a
// plain <img>. Only numbers and fixed labels are drawn — never the self-declared,
// attacker-controllable location strings — so there is nothing to escape.

// Brand palette (mirrors the dashboard's paper theme).
const (
	svgPaper  = "#f4f1e9"
	svgInk    = "#1c1e1a"
	svgInk2   = "#54584e"
	svgLine   = "#d4ccb8"
	svgHub    = "#173a5e" // accent blue
	svgProbe  = "#15803d" // up green
	svgAccent = "#173a5e"
)

func (s *Server) handleNetworkBannerSVG(w http.ResponseWriter, r *http.Request) {
	writeSVG(w, renderBannerSVG(s.networkView(r.Context())))
}

func writeSVG(w http.ResponseWriter, svg string) {
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write([]byte(svg))
}

// renderBannerSVG is a compact stats strip for embedding inline (e.g. a README).
func renderBannerSVG(v NetworkView) string {
	const w, h = 720.0, 150.0
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %g %g" font-family="system-ui,sans-serif">`, w, h)
	fmt.Fprintf(&b, `<rect x="0.5" y="0.5" width="%g" height="%g" rx="16" fill="%s" stroke="%s"/>`, w-1, h-1, svgPaper, svgLine)

	// The LibrePing radar mark on the left (its own 64×64 artwork).
	b.WriteString(`<g transform="translate(28 43)">`)
	b.WriteString(`<g stroke="` + svgHub + `" stroke-width="3.2" stroke-linecap="round" fill="none">`)
	b.WriteString(`<path d="M17 34 A13 13 0 0 1 30 47"/>`)
	b.WriteString(`<path d="M17 25 A22 22 0 0 1 39 47" stroke-opacity="0.6"/>`)
	b.WriteString(`<path d="M17 16 A31 31 0 0 1 48 47" stroke-opacity="0.34"/>`)
	b.WriteString(`</g>`)
	fmt.Fprintf(&b, `<circle cx="44" cy="20" r="4" fill="%s"/>`, svgProbe)
	fmt.Fprintf(&b, `<circle cx="17" cy="47" r="5" fill="%s"/>`, svgHub)
	b.WriteString(`</g>`)

	fmt.Fprintf(&b, `<text x="108" y="64" font-size="27" font-weight="700" fill="%s">Libre<tspan fill="%s">Ping</tspan></text>`, svgInk, svgAccent)
	fmt.Fprintf(&b, `<text x="108" y="88" font-size="14" fill="%s">decentralized uptime — live network</text>`, svgInk2)

	stats := []struct {
		n     int
		label string
	}{
		{len(v.Hubs), "hubs"},
		{len(v.Probes), "probes"},
		{v.Countries(), "countries"},
	}
	x := 384.0
	for _, st := range stats {
		fmt.Fprintf(&b, `<text x="%g" y="72" font-size="40" font-weight="700" fill="%s">%d</text>`, x, svgAccent, st.n)
		fmt.Fprintf(&b, `<text x="%g" y="98" font-size="14" fill="%s">%s</text>`, x, svgInk2, st.label)
		x += 112
	}
	b.WriteString(`</svg>`)
	return b.String()
}
