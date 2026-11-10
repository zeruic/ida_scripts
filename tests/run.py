''' Run the test suite: `python tests/run.py [pattern ...]`.

Builds the fixtures, makes one analysed database per fixture, then runs every `tests/test_*.py` whose name contains one of the patterns (all of them without a pattern), each in its own process.
'''

import fcntl
import os
import subprocess
import sys
import time

TESTS = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(TESTS, '.cache')
FIXTURES = os.path.join(TESTS, 'fixtures')
TIMEOUT = 900

def ida_python() -> str:
	''' The Python that has idalib: `IDA_PYTHON`, else IDA's own virtual environment. '''
	path = os.environ.get('IDA_PYTHON') or os.path.expanduser('~/.idapro/venv/bin/python3')
	if not os.path.exists(path):
		sys.exit(f'no Python with idalib at {path}, set IDA_PYTHON')
	return path

def stale(target: str, source: str) -> bool:
	return not os.path.exists(target) or os.path.getmtime(target) < os.path.getmtime(source)

def build() -> None:
	''' Compile every fixture and analyse it once. Serialised across processes, so parallel runs share the cache. '''
	os.makedirs(CACHE, exist_ok=True)
	with open(os.path.join(CACHE, '.lock'), 'w') as lock:
		fcntl.flock(lock, fcntl.LOCK_EX)
		for name in sorted(os.listdir(FIXTURES)):
			if not name.endswith('.c'):
				continue
			source = os.path.join(FIXTURES, name)
			binary = os.path.join(CACHE, name[:-2])
			if stale(binary, source):
				subprocess.run(['clang', '-arch', 'arm64', '-O0', '-o', binary, source], check=True)
			if stale(binary + '.i64', binary):
				subprocess.run([ida_python(), os.path.join(TESTS, 'harness.py'), '--analyze', binary], check=True)

def main() -> int:
	patterns = sys.argv[1:]
	build()
	files = sorted(f for f in os.listdir(TESTS) if f.startswith('test_') and f.endswith('.py'))
	files = [f for f in files if not patterns or any(p in f for p in patterns)]
	failed = []
	for name in files:
		env = dict(os.environ)
		python = ida_python()
		if name.startswith('test_outside_'):
			env['IDA_SCRIPTS_NO_IDA'] = '1'
		started = time.time()
		try:
			result = subprocess.run([python, '-u', os.path.join(TESTS, name)], env=env, capture_output=True, text=True, timeout=TIMEOUT)
			output, code = (result.stdout + result.stderr).strip(), result.returncode
		except subprocess.TimeoutExpired as expired:
			output, code = f'{expired.stdout or ""}{expired.stderr or ""}\ntimed out after {TIMEOUT} s', 1
		summary = next((line for line in reversed(output.splitlines()) if line.startswith(('OK', 'FAILED', 'Ran '))), '')
		status = 'ok  ' if code == 0 else 'FAIL'
		print(f'{status} {name:32} {time.time() - started:5.1f}s  {summary}')
		if code != 0:
			failed.append(name)
			print(output)
		elif 'skipped' in summary:
			print('\n'.join(line for line in output.splitlines() if 'skipped' in line.lower()))
	print(f'\n{len(files) - len(failed)} of {len(files)} test files passed')
	return 1 if failed else 0

if __name__ == '__main__':
	sys.exit(main())
