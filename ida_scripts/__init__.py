''' To use, load the `load.py` script in IDA Pro, or `from ida_scripts import *` wherever IDA's Python is available. Needs IDA 9.0 or newer. '''

__docformat__ = "numpy"

__pdoc__ = {
	'utils' : False,
	'compat' : False,
}

from . import memory, module, struc, func, misc, debugger, session
from .utils import IDAError, DecompileError, DebuggerError, pp, hexdump, jsonable
from .memory import *
from .module import *
from .struc import *
from .func import *
from .misc import *
from .debugger import *
from .session import *

__all__ = ['memory', 'module', 'struc', 'func', 'misc', 'debugger', 'session', 'IDAError', 'DecompileError', 'DebuggerError', 'pp', 'hexdump', 'jsonable']
for _module in (memory, module, struc, func, misc, debugger, session):
	__all__ += [name for name in _module.__all__ if name not in __all__]
