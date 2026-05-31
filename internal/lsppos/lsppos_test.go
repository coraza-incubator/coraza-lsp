package lsppos

import "testing"

func TestUTF16Len(t *testing.T) {
	cases := []struct {
		s    string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"café", 4},     // é is BMP: 1 unit
		{"€", 1},        // BMP
		{"中文", 2},       // BMP CJK
		{"a😀b", 4},      // 😀 (U+1F600) is astral: 2 units
		{"😀😀", 4},       // two astral chars
		{"x→y", 3},      // → is BMP
	}
	for _, c := range cases {
		if got := UTF16Len(c.s); got != c.want {
			t.Errorf("UTF16Len(%q) = %d, want %d", c.s, got, c.want)
		}
	}
}

func TestUTF16ColumnToByte(t *testing.T) {
	// "a😀b": bytes a=1, 😀=4, b=1; UTF-16 units a=1, 😀=2, b=1.
	const s = "a😀b"
	cases := []struct{ col, want int }{
		{0, 0},
		{1, 1}, // start of 😀
		{3, 5}, // after 😀 (2 units), start of b at byte 5
		{4, 6}, // end
		{99, 6},
		{-1, 0},
	}
	for _, c := range cases {
		if got := UTF16ColumnToByte(s, c.col); got != c.want {
			t.Errorf("UTF16ColumnToByte(%q,%d) = %d, want %d", s, c.col, got, c.want)
		}
	}
}

func TestUTF16ColumnToRune(t *testing.T) {
	const s = "a😀b" // runes: a=0,😀=1,b=2 ; utf16: a=0,😀=1..2,b=3
	cases := []struct{ col, want int }{
		{0, 0},
		{1, 1}, // 😀
		{3, 2}, // b (after 2 units of 😀)
		{4, 3},
	}
	for _, c := range cases {
		if got := UTF16ColumnToRune(s, c.col); got != c.want {
			t.Errorf("UTF16ColumnToRune(%q,%d) = %d, want %d", s, c.col, got, c.want)
		}
	}
}
