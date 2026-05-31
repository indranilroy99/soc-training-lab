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
    if (code === 2) {
      // Exit code 2 = EADDRINUSE — do NOT restart, it will just loop forever
      console.error(`[cluster] Worker exited with EADDRINUSE — not restarting. Fix the port conflict first.`);
      if (Object.keys(cluster.workers).length === 0) process.exit(2);  // exit primary too
    } else if (code !== 0 && !worker.exitedAfterDisconnect) {
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
    if (err.code === 'EADDRINUSE') {
      // Port already in use — do NOT let cluster auto-restart (causes infinite loop)
      // This happens if a previous server instance wasn't killed before starting a new one
      console.error(`[worker:${process.pid}] FATAL: Port ${cfg.PORT} is already in use.`);
      console.error(`[worker:${process.pid}] Run: kill $(lsof -ti:${cfg.PORT}) to free the port.`);
      process.exitCode = 2;  // exitCode=2 signals cluster to NOT restart this worker
    } else {
      console.error(`[worker:${process.pid}] Failed to start:`, err.message);
      process.exitCode = 1;
    }
    process.exit(process.exitCode);
  });
}
