"""GuardianX Enforcement — Process control and self-protection.

Lazy imports via __getattr__ to avoid cascading ImportError when
pywin32 is unavailable (ProcessManager, SelfDefense, etc. require it).
"""

__all__ = [
    'ProcessManager',
    'ProcessInspector',
    'WhitelistManager',
    'SelfDefense',
]


def __getattr__(name):
    if name == 'ProcessManager':
        from guardianx.enforcement.process_manager import ProcessManager
        return ProcessManager
    if name == 'ProcessInspector':
        from guardianx.enforcement.inspector import ProcessInspector
        return ProcessInspector
    if name == 'WhitelistManager':
        from guardianx.enforcement.whitelist import WhitelistManager
        return WhitelistManager
    if name == 'SelfDefense':
        from guardianx.enforcement.self_defense import SelfDefense
        return SelfDefense
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

