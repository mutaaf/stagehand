# Agents

- This is shared by several Workers. A change that breaks an existing cookie or token signs the owner out everywhere: the test "cookies issued by the old per-service code still verify" must keep passing.
- Nothing here may log or store a personal field. `log()` drops them; never loosen that regex.
- Release: bump `version`, tag `vX.Y.Z`, then bump the `#vX.Y.Z` in each service's package.json.
- `npm run check` must pass.
