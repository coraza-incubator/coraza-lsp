package parser

import (
	"strings"
	"testing"
)

// A representative multi-line CRS-style rule with variables, an operator with a
// regex containing backslash escapes, transformations, macros and continuations.
const benchRule = `SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|ARGS_NAMES|ARGS|XML:/* "@rx (?i:(?:[\s\x0b]+(?:and|or)[\s\x0b]+))" \
    "id:%d,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:lowercase,\
    msg:'SQL Injection Attack: \"or\"/\"and\" detected',\
    logdata:'Matched Data: %%{TX.0} found within %%{MATCHED_VAR_NAME}',\
    tag:'application-multi',\
    tag:'attack-sqli',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%%{tx.critical_anomaly_score}'"
`

func buildRuleset(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(strings.Replace(benchRule, "%d", "942100", 1))
	}
	return b.String()
}

// BenchmarkParse guards the O(n) parse claim and the absence of the quadratic
// continuation-line lexing regression (fixed in PR #4). ~13 logical lines/rule.
func BenchmarkParse(b *testing.B) {
	for _, n := range []int{1, 100, 1000} {
		src := buildRuleset(n)
		b.Run(sizeLabel(n), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(src)))
			for i := 0; i < b.N; i++ {
				_ = Parse("bench.conf", src)
			}
		})
	}
}

func sizeLabel(n int) string {
	switch n {
	case 1:
		return "1rule"
	case 100:
		return "100rules"
	default:
		return "1000rules"
	}
}
