''' Run the test suite: `python tests/run.py [pattern ...]`.

Prepares the fixtures, makes one analysed database per fixture, then runs every `tests/test_*.py` whose name contains one of the patterns (all of them without a pattern), each in its own process.

The fixtures are arm64 Mach-O programs. On macOS they are compiled from `tests/fixtures/*.c`. Anywhere else the copies kept in `tests/fixtures/bin` are used, which IDA analyses on any system. After changing a fixture, `python tests/run.py --prebuild` (on macOS) refreshes those copies.

The Python that has idalib is `IDA_PYTHON` when set, else the virtual environment in IDA's user folder, else the Python running this script if it has `idapro`.
'''

import contextlib
import importlib.util
import os
import shutil
import subprocess
import sys
import time

TESTS = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(TESTS, '.cache')
FIXTURES = os.path.join(TESTS, 'fixtures')
PREBUILT = os.path.join(FIXTURES, 'bin')
TIMEOUT = 900

def ida_python() -> str:
	''' The Python that has idalib. '''
	chosen = os.environ.get('IDA_PYTHON')
	if chosen:
		if not os.path.exists(chosen):
			sys.exit(f'IDA_PYTHON is {chosen}, which does not exist')
		return chosen
	if sys.platform == 'win32':
		candidates = [os.path.join(os.environ.get('APPDATA', ''), 'Hex-Rays', 'IDA Pro', 'venv', 'Scripts', 'python.exe')]
	else:
		candidates = [os.path.expanduser('~/.idapro/venv/bin/python3')]
	for candidate in candidates:
		if os.path.exists(candidate):
			return candidate
	if importlib.util.find_spec('idapro'):
		return sys.executable
	sys.exit('no Python with idalib found: set IDA_PYTHON to a Python that can `import idapro`')

def can_compile() -> bool:
	''' Whether the fixtures can be compiled here: clang on macOS builds the arm64 Mach-O programs the tests expect.

	`IDA_SCRIPTS_PREBUILT=1` says no, to try the kept copies on a Mac.
	'''
	return sys.platform == 'darwin' and bool(shutil.which('clang')) and os.environ.get('IDA_SCRIPTS_PREBUILT') != '1'

def stale(target: str, source: str) -> bool:
	return not os.path.exists(target) or os.path.getmtime(target) < os.path.getmtime(source)

@contextlib.contextmanager
def locked():
	''' Hold the cache's lock, so runs side by side prepare the fixtures one at a time. '''
	os.makedirs(CACHE, exist_ok=True)
	with open(os.path.join(CACHE, '.lock'), 'a+') as lock:
		if sys.platform == 'win32':
			import msvcrt
			lock.seek(0)
			# LK_LOCK gives up after ten seconds, analysing a fixture can take longer.
			while True:
				try:
					msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
					break
				except OSError:
					time.sleep(1)
			try:
				yield
			finally:
				lock.seek(0)
				msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
		else:
			import fcntl
			fcntl.flock(lock, fcntl.LOCK_EX)
			yield

def fixtures() -> list:
	return sorted(name[:-2] for name in os.listdir(FIXTURES) if name.endswith('.c'))

def build() -> None:
	''' Put every fixture's program and its analysed database into the cache. '''
	with locked():
		for name in fixtures():
			source = os.path.join(FIXTURES, name + '.c')
			prebuilt = os.path.join(PREBUILT, name)
			binary = os.path.join(CACHE, name)
			if can_compile():
				if stale(binary, source):
					subprocess.run(['clang', '-arch', 'arm64', '-O0', '-o', binary, source], check=True)
			elif not os.path.exists(prebuilt):
				sys.exit(f'{prebuilt} is missing, and {name}.c can only be compiled on macOS: run `python tests/run.py --prebuild` there')
			elif stale(binary, prebuilt):
				shutil.copy2(prebuilt, binary)
			if stale(binary + '.i64', binary):
				# idalib would reopen a database that is already there instead of analysing the new program.
				for extension in ('.i64', '.id0', '.id1', '.id2', '.nam', '.til'):
					with contextlib.suppress(FileNotFoundError):
						os.remove(binary + extension)
				subprocess.run([ida_python(), os.path.join(TESTS, 'harness.py'), '--analyze', binary], check=True)

def prebuild() -> int:
	''' Compile every fixture and keep the programs in `tests/fixtures/bin`, for the systems that cannot compile them. '''
	if not can_compile():
		sys.exit('the fixtures are arm64 Mach-O programs: --prebuild needs clang on macOS')
	os.makedirs(PREBUILT, exist_ok=True)
	for name in fixtures():
		source = os.path.join(FIXTURES, name + '.c')
		subprocess.run(['clang', '-arch', 'arm64', '-O0', '-o', os.path.join(PREBUILT, name), source], check=True)
		print(f'built {os.path.join("tests", "fixtures", "bin", name)}')
	return 0

def main() -> int:
	if sys.argv[1:] == ['--prebuild']:
		return prebuild()
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
			result = subprocess.run([python, '-u', os.path.join(TESTS, name)], env=env, capture_output=True, text=True, errors='replace', timeout=TIMEOUT)
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
