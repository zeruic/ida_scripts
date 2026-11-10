''' Stand-ins for IDA's `ida_dbg` and `ida_idd`, backed by a simulated process, for testing the debugger code where no process can be debugged.

`fakes.ida_dbg` and `fakes.ida_idd` define only names that exist in IDA 9.4, with the same parameters (`tests/test_debugger.py` checks this against the real modules). `fakes.process.FakeIDA` is the simulated debugger and process behind them, and `fakes.process.install` puts them in place of the real modules inside `ida_scripts` for one test.
'''

from . import ida_idd, ida_dbg, process
