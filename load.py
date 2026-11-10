# Keeping these allows us to use imports without the module name prefix,
# while still getting the modules to be refreshed properly.
from ida_scripts import *

import sys
import idaapi

MODULES = ['compat', 'utils', 'memory', 'module', 'struc', 'func', 'misc', 'debugger', 'session']

# A module that holds on to something in IDA (hooks, for instance) lets go of it in `_unload`.
for name in reversed(MODULES):
	unload = getattr(sys.modules.get(f'ida_scripts.{name}'), '_unload', None)
	if unload:
		unload()

for name in MODULES:
	idaapi.require(f'ida_scripts.{name}')
idaapi.require('ida_scripts')

from ida_scripts import *
