/* Fixture for tests/test_func.py: another build of some sample.c functions, under other names and at other addresses. Built by tests/run.py with: clang -arch arm64 -O0 */

int counter = 3;

/* First, so that everything after it moves. Its loop jumps inside the function. */
__attribute__((noinline)) int spread(int x) {
	int total = 0;
	for (int i = 0; i < x; i++)
		total += i * x;
	return total;
}

/* The same code as add, mul, leaf and compute in sample.c. */
__attribute__((noinline)) int plus(int a, int b) {
	return a + b;
}

__attribute__((noinline)) int times(int a, int b) {
	return a * b;
}

__attribute__((noinline)) int read_counter(void) {
	return counter;
}

__attribute__((noinline)) int combine(int x) {
	int first = plus(x, 1);
	int second = times(first, 2);
	int third = plus(second, read_counter());
	return third;
}

/* The same code as plus, so neither of them is unique here. */
__attribute__((noinline)) int plus_again(int a, int b) {
	return a + b;
}

__attribute__((noinline)) int recurse(int n) {
	return n > 0 ? recurse(n - 1) : 0;
}

/* A single jump to another function, which IDA makes a thunk. */
__attribute__((naked)) int jump_to_times(int a, int b) {
	__asm__("b _times");
}

int main(int argc, char **argv) {
	return spread(argc) + combine(argc) + plus_again(argc, 2) + recurse(argc) + jump_to_times(argc, 3);
}
