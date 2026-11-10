/* Fixture for tests/test_misc.py: strings in other encodings. Built by tests/run.py with: clang -arch arm64 -O0 */
#include <stdio.h>

/* "テスト cp932" in Shift-JIS (cp932) */
const char sjis_text[] = "\x83\x65\x83\x58\x83\x67 cp932";
/* "café utf8" in UTF-8 */
const char utf8_text[] = "caf\xc3\xa9 utf8";
const unsigned short utf16_text[] = u"utf16 marker";
const char *plain_text = "plain marker text";

__attribute__((noinline)) int uses_sjis(void) {
	return puts(sjis_text) + puts(utf8_text);
}

__attribute__((noinline)) int uses_plain(void) {
	return puts(plain_text) + utf16_text[0];
}

__attribute__((noinline)) int also_plain(void) {
	return puts("plain marker text") + 1;
}

int main(void) {
	return uses_sjis() + uses_plain() + also_plain();
}
