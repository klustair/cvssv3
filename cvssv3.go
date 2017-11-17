// Package cvssv3 provides parsing and scoring with Common Vulunerability
// Scoring System version 3.0 (CVSSv3).
// Author: Bunji2 
// Inspired by "go-cvss" ( https://github.com/umisama/go-cvss ),
// but implementated in different way.
package cvssv3

import (
	"fmt"
	"math"
	"regexp"
)

// Vector reprecents a CVSS vector.
type Vector map[string] string

// Val(x) returns float value of m's metrics x
func (m Vector) Val(x string) float64 {
	val, ok := m[x]
	if ! ok {
		return math.NaN()
	}
	switch x {
	case "AV":
		return val_AV(val)
	case "AC":
		return val_AC(val)
	case "PR":
		return val_PR(val, m.IsScopeChanged())
	case "UI":
		return val_UI(val)
	case "S": // for compatibility...
		if val == "C" {
			return 1.0 // scope is changed
		}
		return 0.0 // scope is unchanged
	case "C", "I", "A":
		return val_Impact(val)
	case "E":
		return val_E(val)
	case "RL":
		return val_RL(val)
	case "RC":
		return val_RC(val)
	case "CR", "IR", "AR":
		return val_Requirements(val)
	case "MAV":
		if val == "X" {
			return m.Val("AV")
		}
		return val_AV(val)
	case "MAC":
		if val == "X" {
			return m.Val("AC")
		}
		return val_AC(val)
	case "MPR":
		if val == "X" {
			return m.Val("PR")
		}
		return val_PR(val, m.IsModifiedScopeChanged())
	case "MUI":
		if val == "X" {
			return m.Val("UI")
		}
		return val_UI(val)
	case "MS": // for compatibility...
		if val == "X" {
			return m.Val("S")
		}
		if val == "C" {
			return 1.0 // scope is changed
		}
		return 0.0 // scope is unchanged
	case "MC":
		if val == "X" {
			return m.Val("C")
		}
		return val_Impact(val)
	case "MI":
		if val == "X" {
			return m.Val("I")
		}
		return val_Impact(val)
	case "MA":
		if val == "X" {
			return m.Val("A")
		}
		return val_Impact(val)
	}
	return math.NaN()
}

// Str(x) returns string value of m's metrics x
func (m Vector) Str(x string) string {
	val, ok := m[x]
	if ok {
		return val
	}
	return "?"
}

func (m Vector) IsScopeChanged() bool {
	if m.Val("S") == 1.0 {
		return true
	}
	return false
}

func (m Vector) IsModifiedScopeChanged() bool {
	if m.Val("MS") == 1.0 {
		return true
	}
	return false
}

// ParseVector create new Vector object with str.
// str must valid as CVSS:3.0/base/temporal/environment Vector.
func ParseVector(str string) (Vector, error) {
	submatches := regexp.MustCompile(
		`CVSS:3.0\/` +
		`AV:([NALP])\/AC:([LH])\/PR:([NLH])\/UI:([NR])\/S:([UC])\/` +
		`C:([HLN])\/I:([HLN])\/A:([HLN])`+
		`(?:\/E:([XUPFH])\/RL:([XOTWU])\/RC:([XURC])` +
			`(?:\/CR:([XHML])\/IR:([XHML])\/AR:([XHML])\/MAV:([XNALP])\/` +
				`MAC:([XLH])\/MPR:([XNLH])\/MUI:([XNR])\/MS:([XUC])\/` +
				`MC:([XHLN])\/MI:([XHLN])\/MA:([XHLN])` +
			`)?` +
		`)?`).FindStringSubmatch(str)
//	fmt.Printf("%s(%d)", str, len(submatches))
	if len(submatches) < 9 || submatches[0] != str {
		return Vector{}, 
			fmt.Errorf("invalid Vector string: %s(%d)", str, len(submatches))
	}

	metrics := map[string]string {
		// mandatory metrics
		"AV":  submatches[1],
		"AC":  submatches[2],
		"PR":  submatches[3],
		"UI":  submatches[4],
		"S":   submatches[5],
		"C":   submatches[6],
		"I":   submatches[7],
		"A":   submatches[8],

		// optional metrics
		"E":   "X",
		"RL":  "X",
		"RC":  "X",
		"CR":  "X",
		"IR":  "X",
		"AR":  "X",
		"MAV": "X",
		"MAC": "X",
		"MPR": "X",
		"MUI": "X",
		"MS":  "X",
		"MC":  "X",
		"MI":  "X",
		"MA":  "X",
	}
	if len(submatches) > 11 {
		if submatches[9] != "" {
			metrics["E"] =  submatches[9]
		}
		if submatches[10] != "" {
			metrics["RL"] = submatches[10]
		}
		if submatches[11] != "" {
			metrics["RC"] = submatches[11]
		}
	}
	if len(submatches) > 22 {
		if submatches[12] != "" {
			metrics["CR"] =  submatches[12]
		}
		if submatches[13] != "" {
			metrics["IR"] =  submatches[13]
		}
		if submatches[14] != "" {
			metrics["AR"] =  submatches[14]
		}
		if submatches[15] != "" {
			metrics["MAV"] = submatches[15]
		}
		if submatches[16] != "" {
			metrics["MAC"] = submatches[16]
		}
		if submatches[17] != "" {
			metrics["MPR"] = submatches[17]
		}
		if submatches[18] != "" {
			metrics["MUI"] = submatches[18]
		}
		if submatches[19] != "" {
			metrics["MS"] =  submatches[19]
		}
		if submatches[20] != "" {
			metrics["MC"] =  submatches[20]
		}
		if submatches[21] != "" {
			metrics["MI"] =  submatches[21]
		}
		if submatches[22] != "" {
			metrics["MA"] =  submatches[22]
		}
	}

	m := Vector(metrics)

	//fmt.Println(metrics)
	return m, nil

}


// String returns formatted m.
func (m Vector) String() string {
	prefix := "CVSS:3.0"

	base := "AV:" + m.Str("AV") + "/AC:" + m.Str("AC") +
		"/PR:" + m.Str("PR") + "/UI:" + m.Str("UI") +
		"/S:" + m.Str("S") + "/C:" + m.Str("C") +
		"/I:" + m.Str("I") + "/A:" + m.Str("A")

	temp := "E:" + m.Str("E") + "/RL:" + m.Str("RL") + 
		"/RC:" + m.Str("RC")

	env := "CR:" + m.Str("CR") + "/IR:" + m.Str("IR") + 
		"/AR:" + m.Str("AR") + "/MAV:" + m.Str("MAV") + 
		"/MAC:" + m.Str("MAC") + "/MPR:" + m.Str("MPR") + 
		"/MUI:" + m.Str("MUI") + "/MS:" + m.Str("MS") + 
		"/MC:" + m.Str("MC") + "/MI:" + m.Str("MI") + 
		"/MA:" + m.Str("MA")

	return prefix + "/" + base + "/" + temp + "/" + env
}

// BaseScore returns m's base score.
func (m Vector) BaseScore() float64 {
	scope_changed := m.IsModifiedScopeChanged()
	c := m.Val("C")
	i := m.Val("I")
	a := m.Val("A")
	isc := calc_isc(c, i, a)
	impact := calc_impact(scope_changed, isc)

	if impact <= 0.0 {
		return 0.0
	}

	av := m.Val("AV")
	ac := m.Val("AC")
	pr := m.Val("PR")
	ui := m.Val("UI")
	exploitability := calc_exploitability(av, ac, pr, ui)
	
	base := calc_base(scope_changed, impact, exploitability)
	return roundUp1(base)
}

// TemporalScore returns m's temporal score.
func (m Vector) TemporalScore() float64 {
	base := m.BaseScore()
	e := m.Val("E")
	rl := m.Val("RL")
	rc := m.Val("RC")
	temp := calc_temporal(base, e, rl, rc)
	return roundUp1(temp)
}

func (m Vector) EnvironmentalScore() float64 {
	m_scope_changed := m.IsModifiedScopeChanged()
	cr := m.Val("CR")
	ir := m.Val("IR")
	ar := m.Val("AR")
	mc := m.Val("MC")
	mi := m.Val("MI")
	ma := m.Val("MA")
	m_isc := calc_modified_isc(cr, ir, ar, mc, mi, ma)
	m_impact := calc_impact(m_scope_changed, m_isc)

	if m_impact <= 0.0 {
		return 0.0
	}

	mav := m.Val("MAV")
	mac := m.Val("MAC")
	mpr := m.Val("MPR")
	mui := m.Val("MUI")
	m_exploitability := calc_exploitability(mav, mac, mpr, mui)

	m_base := calc_base(m_scope_changed, m_impact, m_exploitability)

	me := m.Val("E")
	mrl := m.Val("RL")
	mrc := m.Val("RC")
	m_temp := calc_temporal(m_base, me, mrl, mrc)
	return roundUp1(m_temp)
}

func calc_base(scope_changed bool, impact, exploitability float64) float64 {
	a := float64(1.0)
	if scope_changed {
		a = float64(1.08)
	}
	return math.Min(a*(impact+exploitability), 10.0)
}

func calc_impact(scope_changed bool, isc float64) float64 {
	if !scope_changed {
		return 6.42 * isc
	}
	return 7.52 * (isc - 0.029) - 3.25 * math.Pow((isc - 0.02), 15.0)
}

func calc_isc(c, i, a float64) float64 {
	return float64(1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a))
}

func calc_exploitability(av, ac, pr, ui float64) float64 {
	return 8.22 * av * ac * pr * ui
}

func calc_temporal(base, e, rl, rc float64) float64 {
	return base * e * rl * rc
}

func calc_modified_isc(cr, ir, ar, c, i, a float64) float64 {
	return math.Min(
		float64(1.0 - (1.0 - c * cr) * (1.0 - i * ir) * (1.0 - a * ar)),
		0.915)
}

func roundUp1(val float64) float64 {
	return math.Ceil(val*10)/10
}

func val_AV(v string) float64 {
	switch v {
	case "N":
		return 0.85
	case "A":
		return 0.62
	case "L":
		return 0.55
	}
//	case "P":
	return 0.2
}

func val_AC(v string) float64 {
	switch v {
	case "L":
		return 0.77
	}
//	case "H":
	return 0.44
}

func val_PR(v string, scope_changed bool) float64 {
	switch v {
	case "L":
		if scope_changed {
			return 0.68
		}
		return 0.62
	case "H":
		if scope_changed {
			return 0.50
		}
		return 0.27
	}
//	case "N":
	return 0.85
}

func val_UI(v string) float64 {
	switch v {
	case "R":
		return 0.62
	}
//	case "N":
	return 0.85
}

func val_Impact(v string) float64 {
	switch v {
	case "H":
		return 0.56
	case "L":
		return 0.22
	}
//	case "N":
	return 0.0
}

func val_E(v string) float64 {
	switch v {
	case "F":
		return 0.97
	case "P":
		return 0.94
	case "U":
		return 0.91
	}
//	case "X", "H":
	return 1.0
}

func val_RL(v string) float64 {
	switch v {
	case "W":
		return 0.97
	case "T":
		return 0.96
	case "O":
		return 0.95
	}
//	case "X", "U":
	return 1.0
}

func val_RC(v string) float64 {
	switch v {
	case "R":
		return 0.96
	case "U":
		return 0.92
	}
//	case "X", "C":
	return 1.0
}

func val_Requirements(v string) float64 {
	switch v {
	case "H":
		return 1.5
	case "L":
		return 0.5
	}
//	case "X", "M":
	return 1.0
}

// End of package cvssv3