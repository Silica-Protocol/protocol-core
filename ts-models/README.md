# @chert/ts-models

Shared TypeScript domain models for Chert frontends (wallet, explorer, operations dashboards).

## Usage

```bash
npm install --save-dev @chert/ts-models
```

```ts
import type { BlockSummary } from '@chert/ts-models';

function renderBlock(block: BlockSummary): void {
  console.log(block.hash, block.transactionCount);
}
```

## Development

```bash
npm install
npm run build
npm run test
```
