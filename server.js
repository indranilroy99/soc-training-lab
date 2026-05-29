'use strict';

// ── Entry point ────────────────────────────────────────────────────────────
// This file does ONE thing: manage the cluster.
// All application logic lives in app.js, routes/, services/, and middleware/.

const cluster = require('cluster');
const os      = require('os');
const cfg     = require('./config');

if (cluster.isPrimary) {
  const numWorkers = Math.min(
    Math.max(cfg.CLUSTER_MIN_WORKERS, os.cpus().length - 2),
    cfg.CLUSTER_MAX_WORKERS
  );

  console.log(`\n  DIAAS-SEC Training Platform`);
  console.log(`  Workers : ${numWorkers} (of ${os.cpus().length} CPU cores)`);
  console.log(`  Port    : ${cfg.PORT}`);
  console.log(`  URL     : http://0.0.0.0:${cfg.PORT}\n`);

  for (let i = 0; i < numWorkers; i++) cluster.fork();

  cluster.on('exit', (worker, code, signal) => {
    if (code !== 0 && !worker.exitedAfterDisconnect) {
      console.error(`[cluster] Worker ${worker.process.pid} died (code=${code}, signal=${signal}) — restarting`);
      cluster.fork();
    }
  });

} else {
  // Worker process: start the actual HTTP server
  const { startServer } = require('./app');

  startServer(cfg.PORT, cfg.HOST).then(() => {
    console.log(`[worker:${process.pid}] Listening on ${cfg.HOST}:${cfg.PORT}`);
  }).catch(err => {
    console.error(`[worker:${process.pid}] Failed to start:`, err.message);
    process.exit(1);
  });
}
