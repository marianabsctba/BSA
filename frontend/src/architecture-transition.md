# Frontend modularization transition

The runtime is being migrated from the historical single-file console into small, testable modules. `App.jsx` is intentionally kept as a composition entrypoint. `LegacyConsole.jsx` temporarily preserves runtime behavior while feature slices are extracted behind CI-guarded seams.

Migration order: shell/navigation, login/auth UI, EASM, DRP/CTI/leaks, CTEM, overview, then remaining administration/reporting views. The transition is complete only when the legacy console no longer contains feature implementations.
