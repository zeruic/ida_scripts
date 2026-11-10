/* The process tests/test_debugger_live.py debugs.

It writes ida_scripts_debug_target.report into its working directory (its pid, the tick count it was given, and the addresses of tick and counter), then calls tick(1) ten times a second, as many times as its first argument says (600 by default).
Plain C that MSVC, clang and gcc all build: tick and counter are exported on Windows, so IDA has their names even without debug information.
*/

#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#define EXPORTED __declspec(dllexport)
#define current_pid() _getpid()
#define pause_briefly() Sleep(100)
#else
#include <unistd.h>
#define EXPORTED
#define current_pid() getpid()
#define pause_briefly() usleep(100000)
#endif

EXPORTED volatile int counter = 0;

EXPORTED int tick(int step)
{
	counter += step;
	return counter;
}

int main(int argc, char **argv)
{
	int ticks = argc > 1 ? atoi(argv[1]) : 600;
	int i;
	FILE *report = fopen("ida_scripts_debug_target.report", "w");
	if (report) {
		fprintf(report, "%d %d %p %p\n", (int)current_pid(), ticks, (void *)tick, (void *)&counter);
		fclose(report);
	}
	for (i = 0; i < ticks; i++) {
		tick(1);
		pause_briefly();
	}
	return 0;
}
