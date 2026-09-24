# Architecture Profile
Generated: 2026-09-17

Confidence: none — manual review required

## Detected Patterns

Detected: none

No catalogued pattern reaches Medium confidence. The repository is a single-file
command-line tool (`ssh-audit.py`) with a flat `test/` directory.

### Pipe and Filter — Low confidence
Evidence:
- `audit()` runs a linear flow: `SSH.Socket.connect` → `get_banner` → `read_packet`
  → `SSH2.Kex.parse` / `SSH1.PublicKeyMessage.parse` → `output()`.
- There are no `pipeline/`, `filters/` or `processors/` directories and no stage
  abstraction; the "stages" are plain function calls inside one module.

## Detected Combination
none

## Inferred Structural Rules
none

## Ambiguities & Contradictions
- Protocol classes (`SSH.Socket`, `SSH2.Kex`) reach the module-level `out` singleton,
  which is defined at the bottom of the file, and `SSH.Socket` calls `sys.exit`.
  Wire parsing, the network transport and presentation are therefore not separated.
  With no declared architecture this is recorded here as an observation, not a violation.
