"""Empty on purpose: its presence makes pytest add this project's root to sys.path,
so tests can `import network_scanner`, `import export`, etc. despite the flat
(non-package) layout.
"""
