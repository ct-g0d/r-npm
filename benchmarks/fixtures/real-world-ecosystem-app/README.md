# Real-World Ecosystem App Benchmark Fixture

This fixture models a production-grade full-stack TypeScript/React/Express application representing standard ecosystem constraints:
- **Core HTTP & Utility Dependencies**: `express`, `lodash`, `chalk`
- **Component & Peer Dependencies**: `react` and `react-dom` (with `peerDependencies: { "react": "^18.2.0" }`)
- **CLI Tooling & Shims**: `typescript` (`tsc`, `tsserver`), `prettier` (`prettier`), `mock-cli-helper` (`cli-helper`)
- **Lifecycle Script Hooks**: `preinstall`, `postinstall`, `build`, `test`, `format`
- **Windows .bin Shim Execution & Argument Propagation**
