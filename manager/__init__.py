"""Optional layer over `appsec-compose scan`: named projects, batch runs, schedules, a local UI.

The scanner itself stays stateless. Everything that remembers anything lives
here, in the user's XDG directories, and a user who never runs `project` or
`serve` never touches it. Standard library + the PyYAML the host already needs.
"""
