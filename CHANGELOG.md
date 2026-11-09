# @toruslabs/metadata-helpers

## 9.0.0

### Major Changes

- 0870714: Require Node `>=24.22.0` and npm `>=12`. Publish TypeScript declarations from `dist/lib.cjs/index.d.ts`. Remove the unused `@babel/runtime` peer dependency. The Vite+ build does not reference it.

  Publish one bundled file per format. Version 8.2.0 published one file per module, so an import of a path inside `dist/`, such as `dist/lib.cjs/helpers/crypto.js`, no longer resolves.

  `getDeviceShare` returns `null` when the subspace is missing. Version 8.2.0 returned `undefined` in that case, so a check for `share === undefined` no longer matches.
