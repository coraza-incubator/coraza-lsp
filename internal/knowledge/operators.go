// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package knowledge

// allOperators contains all known SecLang operators with full documentation.
// Operators are used with the @ prefix in SecRule directives.
var allOperators = []Item{
	{
		Name:    "rx",
		Summary: "Match using a PCRE regular expression (default operator)",
		Syntax:  "@rx PATTERN",
		Example: `SecRule ARGS "@rx (?i)<script" "id:1,phase:2,deny"`,
		Description: "**@rx** matches the target variable against a Perl-Compatible Regular Expression (PCRE).\n" +
			"This is the default operator — if no `@operator` is specified, `@rx` is used.\n\n" +
			"Supports the full PCRE feature set including lookahead, named capture groups,\n" +
			"and case-insensitive matching via `(?i)`.",
	},
	{
		Name:    "pm",
		Summary: "Phrase match using Aho-Corasick multi-pattern matching",
		Syntax:  "@pm WORD1 WORD2 ...",
		Example: `SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap nikto nmap" "id:2,phase:1,deny"`,
		Description: "**@pm** performs case-insensitive multi-pattern matching using the Aho-Corasick algorithm.\n" +
			"Faster than `@rx` for matching many fixed strings simultaneously.\n\n" +
			"Patterns are space-separated; the operator matches if *any* pattern is found.",
	},
	{
		Name:    "pmFromFile",
		Aliases: []string{"pmf"},
		Summary: "Phrase match loading patterns from an external file",
		Syntax:  "@pmFromFile /path/to/patterns.txt",
		Example: `SecRule REQUEST_URI "@pmFromFile /etc/coraza/bad-urls.txt" "id:3,phase:1,deny"`,
		Description: "**@pmFromFile** is identical to `@pm` but reads patterns from a file (one pattern per line).\n" +
			"Lines starting with `#` are comments. The alias `@pmf` is also accepted.",
	},
	{
		Name:    "contains",
		Summary: "Check if the target string contains a substring (case-sensitive)",
		Syntax:  "@contains SUBSTRING",
		Example: `SecRule ARGS "@contains ../../../" "id:4,phase:2,deny"`,
		Description: "**@contains** returns true when the target value contains the specified substring.\n" +
			"Case-sensitive; use `t:lowercase` for case-insensitive matching.",
	},
	// Note: `@containsWord` is intentionally absent. Coraza v3.5.0 does NOT
	// register it (internal/operators has no containsWord); Coraza rejects it
	// at parse time with `operator containsWord not found`.
	{
		Name:    "beginsWith",
		Summary: "Check if the target starts with a string",
		Syntax:  "@beginsWith PREFIX",
		Example: `SecRule REQUEST_URI "@beginsWith /admin" "id:6,phase:1,deny"`,
		Description: "**@beginsWith** returns true when the target value starts with the given prefix. Case-sensitive.",
	},
	{
		Name:    "endsWith",
		Summary: "Check if the target ends with a string",
		Syntax:  "@endsWith SUFFIX",
		Example: `SecRule REQUEST_FILENAME "@endsWith .bak" "id:7,phase:1,deny"`,
		Description: "**@endsWith** returns true when the target value ends with the given suffix. Case-sensitive.",
	},
	{
		Name:    "streq",
		Summary: "Exact string equality comparison",
		Syntax:  "@streq STRING",
		Example: `SecRule REQUEST_METHOD "@streq GET" "id:8,phase:1,pass"`,
		Description: "**@streq** returns true when the target value exactly equals the given string. Case-sensitive.\n" +
			"Use `t:lowercase` for case-insensitive comparison.",
	},
	{
		Name:    "strmatch",
		Summary: "Fast string matching using Boyer-Moore-Horspool algorithm",
		Syntax:  "@strmatch PATTERN",
		Example: `SecRule ARGS "@strmatch union+select" "id:9,phase:2,deny"`,
		Description: "**@strmatch** uses the Boyer-Moore-Horspool algorithm for fast single-pattern string matching.\n" +
			"More efficient than `@rx` for simple fixed-string searches.",
	},
	{
		Name:    "within",
		Summary: "Check if the target value is within a whitelist of values",
		Syntax:  "@within VALUE1 VALUE2 ...",
		Example: `SecRule REQUEST_METHOD "!@within GET POST HEAD OPTIONS" "id:10,phase:1,deny"`,
		Description: "**@within** returns true when the entire target value exactly matches one of the\n" +
			"space-separated arguments. Case-sensitive.",
	},
	{
		Name:    "eq",
		Summary: "Numeric equality comparison",
		Syntax:  "@eq NUMBER",
		Example: `SecRule RESPONSE_STATUS "@eq 200" "id:11,phase:3,pass"`,
		Description: "**@eq** compares the target as a number and returns true when equal.\n" +
			"Both target and argument are converted to integers before comparison.",
	},
	// Note: `@ne` is intentionally absent. Coraza v3.5.0 does NOT register a
	// `ne` operator; it rejects `@ne` at parse time with `operator ne not
	// found`. Use `!@eq` for a numeric not-equal test.
	{
		Name:    "gt",
		Summary: "Numeric greater-than comparison",
		Syntax:  "@gt NUMBER",
		Example: `SecRule ARGS_COMBINED_SIZE "@gt 65536" "id:13,phase:2,deny"`,
		Description: "**@gt** returns true when the target numeric value is greater than the argument.",
	},
	{
		Name:    "ge",
		Summary: "Numeric greater-than-or-equal comparison",
		Syntax:  "@ge NUMBER",
		Example: `SecRule TX:anomaly_score "@ge 5" "id:14,phase:2,deny"`,
		Description: "**@ge** returns true when the target numeric value is greater than or equal to the argument.",
	},
	{
		Name:    "lt",
		Summary: "Numeric less-than comparison",
		Syntax:  "@lt NUMBER",
		Example: `SecRule TX:score "@lt 1" "id:15,phase:5,pass"`,
		Description: "**@lt** returns true when the target numeric value is less than the argument.",
	},
	{
		Name:    "le",
		Summary: "Numeric less-than-or-equal comparison",
		Syntax:  "@le NUMBER",
		Example: `SecRule HIGHEST_SEVERITY "@le 2" "id:16,phase:5,deny"`,
		Description: "**@le** returns true when the target numeric value is less than or equal to the argument.",
	},
	{
		Name:    "detectSQLi",
		Summary: "Detect SQL injection using LibInjection heuristics",
		Syntax:  "@detectSQLi",
		Example: `SecRule ARGS "@detectSQLi" "id:17,phase:2,deny,msg:'SQL Injection Detected'"`,
		Description: "**@detectSQLi** uses the LibInjection library to detect SQL injection patterns.\n" +
			"More robust than regex-based detection; adapts to encoding evasion techniques.\n" +
			"No argument required.",
	},
	{
		Name:    "detectXSS",
		Summary: "Detect cross-site scripting using LibInjection heuristics",
		Syntax:  "@detectXSS",
		Example: `SecRule ARGS "@detectXSS" "id:18,phase:2,deny,msg:'XSS Detected'"`,
		Description: "**@detectXSS** uses the LibInjection library to detect XSS patterns in HTML context.\n" +
			"No argument required.",
	},
	{
		Name:    "ipMatch",
		Summary: "Match client IP against IPv4/IPv6 addresses or CIDR ranges",
		Syntax:  "@ipMatch IP|CIDR [IP|CIDR ...]",
		Example: `SecRule REMOTE_ADDR "@ipMatch 192.168.0.0/16 10.0.0.0/8" "id:19,phase:1,allow"`,
		Description: "**@ipMatch** checks the target against a list of IP addresses and CIDR ranges.\n" +
			"Supports both IPv4 and IPv6. Multiple entries are space-separated.",
	},
	{
		Name:    "ipMatchFromFile",
		Aliases: []string{"ipMatchF"},
		Summary: "Match client IP against a list loaded from a file",
		Syntax:  "@ipMatchFromFile /path/to/ips.txt",
		Example: `SecRule REMOTE_ADDR "@ipMatchFromFile /etc/coraza/blocklist.txt" "id:20,phase:1,deny"`,
		Description: "**@ipMatchFromFile** reads IP addresses and CIDR ranges from a file (one per line)\n" +
			"and checks the target against them. The alias `@ipMatchF` is also accepted.",
	},
	{
		Name:    "validateByteRange",
		Summary: "Check that all bytes in the target are within allowed ranges",
		Syntax:  "@validateByteRange RANGE [RANGE ...]",
		Example: `SecRule REQUEST_URI "@validateByteRange 32-126" "id:21,phase:1,deny"`,
		Description: "**@validateByteRange** verifies that every byte in the target value falls within\n" +
			"the specified ranges (hyphen notation: `32-126`).\n\n" +
			"Use to enforce printable ASCII or reject null bytes.",
	},
	{
		Name:    "validateUrlEncoding",
		Summary: "Check that URL-encoded sequences are valid",
		Syntax:  "@validateUrlEncoding",
		Example: `SecRule REQUEST_URI "@validateUrlEncoding" "id:22,phase:1,deny"`,
		Description: "**@validateUrlEncoding** verifies that all `%XX` sequences in the target are valid\n" +
			"URL encoding. Returns true (match) when invalid sequences are found.",
	},
	{
		Name:    "validateUtf8Encoding",
		Summary: "Check that the target contains valid UTF-8 sequences",
		Syntax:  "@validateUtf8Encoding",
		Example: `SecRule REQUEST_URI|ARGS "@validateUtf8Encoding" "id:23,phase:1,deny"`,
		Description: "**@validateUtf8Encoding** returns true when the target contains invalid or overlong\n" +
			"UTF-8 byte sequences.",
	},
	// Note: `@verifyCC` is intentionally absent. Coraza v3.5.0 does NOT register
	// it; it rejects `@verifyCC` at parse time with `operator verifyCC not
	// found`. (ModSecurity ships verifyCC/verifyCPF/verifySSN; Coraza does not.)
	{
		Name:    "noMatch",
		Summary: "Always returns false (never matches)",
		Syntax:  "@noMatch",
		Example: `SecRule ARGS "@noMatch" "id:25,phase:2,pass"`,
		Description: "**@noMatch** always returns false. Useful as a placeholder during development\n" +
			"or for rules that should currently never trigger.",
	},
	{
		Name:    "unconditionalMatch",
		Summary: "Always returns true (always matches)",
		Syntax:  "@unconditionalMatch",
		Example: `SecRule ARGS "@unconditionalMatch" "id:26,phase:2,deny"`,
		Description: "**@unconditionalMatch** always returns true regardless of the target value.\n" +
			"Useful for unconditional logging or actions that must fire for every request.",
	},
	{
		Name:    "geoLookup",
		Summary: "Perform a GeoIP lookup on the target IP address",
		Syntax:  "@geoLookup",
		Example: `SecRule REMOTE_ADDR "@geoLookup" "id:27,phase:1,pass"`,
		Description: "**@geoLookup** performs a GeoIP database lookup on the target IP address and populates\n" +
			"the `GEO` collection with country code, city, latitude, longitude, and other data.\n" +
			"Requires a GeoIP database to be configured.",
	},
	{
		Name:    "rbl",
		Summary: "Check an IP address against a real-time block list (DNSBL)",
		Syntax:  "@rbl dnsbl.example.com",
		Example: `SecRule REMOTE_ADDR "@rbl zen.spamhaus.org" "id:28,phase:1,deny"`,
		Description: "**@rbl** checks the target IP address against a DNS-based blocklist (DNSBL/RBL).\n" +
			"Returns true when the IP is listed in the blocklist.",
	},
	{
		Name:    "inspectFile",
		Summary: "Pass uploaded file to an external program for inspection",
		Syntax:  "@inspectFile /path/to/script",
		Example: `SecRule FILES_TMPNAMES "@inspectFile /usr/local/bin/modsec-clamscan.pl" "id:29,phase:2,deny"`,
		Description: "**@inspectFile** executes an external script/program, passing the file path as an\n" +
			"argument. Returns true when the program returns a non-zero exit code.",
	},
	// Note: `@fuzzyHash` is intentionally absent. Coraza v3.5.0 does NOT register
	// it; it rejects `@fuzzyHash` at parse time with `operator fuzzyHash not
	// found`. (ModSecurity's ssdeep-based operator is not implemented in Coraza.)
	{
		Name:    "ipMatchFromDataset",
		Summary: "Match client IP against a dataset of IP addresses and CIDR ranges",
		Syntax:  "@ipMatchFromDataset DATASET_NAME",
		Example: `SecRule REMOTE_ADDR "@ipMatchFromDataset blocklist" "id:31,phase:1,deny"`,
		Description: "**@ipMatchFromDataset** checks the target IP address against a named dataset loaded with `SecDataset`.\n" +
			"The dataset should contain one IP address or CIDR range per line.\n\n" +
			"Equivalent to `@ipMatchFromFile` but uses pre-loaded datasets for better performance.",
	},
	{
		Name:    "pmFromDataset",
		Summary: "Phrase match using patterns from a named dataset",
		Syntax:  "@pmFromDataset DATASET_NAME",
		Example: `SecRule REQUEST_HEADERS:User-Agent "@pmFromDataset bad-agents" "id:32,phase:1,deny"`,
		Description: "**@pmFromDataset** performs case-insensitive multi-pattern matching using patterns from a\n" +
			"named dataset loaded with `SecDataset`. Equivalent to `@pmFromFile` but uses pre-loaded datasets.\n\n" +
			"The dataset should contain one pattern per line; lines starting with `#` are comments.",
	},
	{
		Name:    "restpath",
		Summary: "Match a URL path against a REST path template with named capture groups",
		Syntax:  "@restpath /template/{variable}",
		Example: `SecRule REQUEST_URI "@restpath /api/users/{id}/posts/{postId}" "id:33,phase:1,pass,setvar:TX.user_id=%{TX.id}"`,
		Description: "**@restpath** matches the target against a REST-style path template.\n" +
			"Segments enclosed in `{name}` are named capture groups whose values are stored in `TX.name`.\n\n" +
			"Returns true when the path matches the template. Useful for extracting REST resource identifiers.",
	},
	{
		Name:    "validateNid",
		Summary: "Validate a national identity document number (NID)",
		Syntax:  "@validateNid TYPE",
		Example: `SecRule ARGS "@validateNid uk_ni" "id:34,phase:2,block,msg:'NI number in request'"`,
		Description: "**@validateNid** validates the target against a known national identification number format.\n" +
			"Returns true when a valid NID is found, which may indicate sensitive data in the request.\n\n" +
			"Supported types vary by deployment. Common values: `uk_ni`, `es_dni`, `us_ssn`.",
	},
	{
		Name:    "validateSchema",
		Summary: "Validate the target XML against an XML Schema Definition (XSD)",
		Syntax:  "@validateSchema /path/to/schema.xsd",
		Example: `SecRule XML "@validateSchema /etc/coraza/schemas/soap.xsd" "id:35,phase:2,deny,msg:'Invalid XML schema'"`,
		Description: "**@validateSchema** validates the parsed XML target against the specified XSD schema file.\n" +
			"Returns true (match) when the XML document does **not** conform to the schema.\n\n" +
			"Use to enforce strict XML structure and reject malformed SOAP or XML API requests.",
	},
}
