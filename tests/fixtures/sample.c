/* Shared test fixture. Built by tests/run.py with: clang -arch arm64 -O0 */
#include <stdio.h>
#include <string.h>

struct Vec2 {
	float x;
	float y;
};

struct Player {
	int id;
	short level;
	unsigned char flags;
	char name[16];
	struct Vec2 position;
	double score;
	const char *title;
	int inventory[4];
	struct Player *next;
};

int counter = 7;
unsigned short small_value = 0xBEEF;
long long big_value = -1234567890123LL;
float single_value = 1.5f;
double double_value = 2.25;
const int table[4] = { 10, 20, 30, 40 };
const char *message = "pointer target";
const unsigned short wide_text[] = u"wide fixture";
const char narrow_text[] = "narrow fixture";

struct Player sidekick = { 2, 3, 1, "sidekick", { 0.5f, -0.5f }, 12.5, "the second", { 5, 6, 7, 8 }, 0 };
struct Player hero = { 1, 42, 0x80, "hero", { 1.0f, 2.0f }, 99.5, "the first", { 1, 2, 3, 4 }, &sidekick };

typedef int (*binary_op)(int, int);

__attribute__((noinline)) int add(int a, int b) {
	return a + b;
}

__attribute__((noinline)) int mul(int a, int b) {
	return a * b;
}

__attribute__((noinline)) int leaf(void) {
	return counter;
}

__attribute__((noinline)) int compute(int x) {
	int first = add(x, 1);
	int second = mul(first, 2);
	int third = add(second, leaf());
	return third;
}

__attribute__((noinline)) int apply(binary_op op, int a, int b) {
	return op(a, b);
}

__attribute__((noinline)) int tail_caller(int a, int b) {
	__attribute__((musttail)) return add(a, b);
}

__attribute__((noinline)) int dispatch(int op, int a, int b) {
	switch (op) {
	case 0: return add(a, b);
	case 1: return mul(a, b);
	case 2: return a - b;
	case 3: return a / (b ? b : 1);
	case 4: return a % (b ? b : 1);
	case 5: return a & b;
	case 6: return a | b;
	case 7: return a ^ b;
	default: return -1;
	}
}

__attribute__((noinline)) void greet(const char *who) {
	printf("hello fixture %s\n", who);
}

__attribute__((noinline)) int player_power(struct Player *player) {
	return player->level * 2 + player->inventory[1] + (int)player->score;
}

__attribute__((noinline)) int this_is_a_very_long_function_name_used_to_test_identifier_shortening(int value) {
	return value + 1;
}

__attribute__((noinline)) int uses_strings(void) {
	return (int)strlen(narrow_text) + (int)strlen(message);
}

int main(int argc, char **argv) {
	int total = compute(argc);
	total += apply(add, 3, 4);
	total += tail_caller(5, 6);
	total += dispatch(argc, 8, 2);
	total += player_power(&hero);
	total += this_is_a_very_long_function_name_used_to_test_identifier_shortening(argc);
	total += uses_strings();
	total += table[argc & 3] + small_value + (int)big_value + (int)single_value + (int)double_value + wide_text[0];
	greet(argv[0]);
	return total & 0xff;
}
