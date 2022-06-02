import os

import angr
from angr.analyses import CFGFast

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_thunks():
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "bf")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()()

    # This is the thunk of _getc
    # Somehow the CFGFast analysis might decide that this is non-returning
    func = cfg.functions[0x100003f24]

    # This isn't decided by any SimProc related handling
    assert func._get_initial_returning() is None

    assert len(func.endpoints) > 0
    assert func.returning
