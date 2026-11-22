import 'dotenv/config';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createApiRouter } from './server/routes.ts';
import { SentinelStore } from './server/store.ts';

export async function createServer(options?: { dataDir?: string; skipVite?: boolean }) {
  const app = express();
  app.use(express.json({ limit: '4mb' }));

  const store = new SentinelStore(options?.dataDir);
  app.use('/api', createApiRouter(store));

  const isProd = process.env.NODE_ENV === 'production';

  if (!options?.skipVite) {
    if (!isProd) {
      const { createServer: createViteServer } = await import('vite');
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: 'spa',
      });
      app.use(vite.middlewares);
    } else {
      const distDir = path.resolve(process.cwd(), 'dist');
      if (fs.existsSync(distDir)) {
        app.use(express.static(distDir));
        app.get('*splat', (_req, res) => {
          res.sendFile(path.join(distDir, 'index.html'));
        });
      }
    }
  }

  return { app, store };
}

const isMainModule =
  typeof process.argv[1] === 'string' &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isMainModule) {
  const PORT = Number(process.env.PORT || 3000);
  const { app } = await createServer();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SENTINELFORGE SOC Platform running on http://0.0.0.0:${PORT}`);
  });
}
