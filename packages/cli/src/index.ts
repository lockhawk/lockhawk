import { Command, Option } from 'commander';
import { runScan } from './commands/scan.js';
import type { ScanCliOptions } from './commands/scan.js';
import type { Format } from './report/render.js';
import { runReport } from './commands/report.js';
import { runServe } from './commands/serve.js';

const program = new Command();

program
  .name('npm-scanner')
  .description(
    'Fast, free, accurate npm dependency vulnerability scanner (local + CI/CD), powered by OSV.dev',
  )
  .version('0.1.0');

const severityChoices = ['none', 'low', 'medium', 'high', 'critical'];

program
  .command('scan', { isDefault: true })
  .description('Scan a project for vulnerable dependencies')
  .argument('[path]', 'project directory to scan', '.')
  .addOption(
    new Option('-f, --format <format>', 'output format')
      .choices(['table', 'json', 'sarif', 'html'])
      .default('table'),
  )
  .option('-o, --output <file>', 'write the report to a file instead of stdout')
  .addOption(
    new Option('--severity-threshold <level>', 'minimum severity to report').choices(
      severityChoices,
    ),
  )
  .addOption(
    new Option('--fail-on <level>', 'minimum severity that causes a non-zero exit')
      .choices(severityChoices)
      .default('high'),
  )
  .option('--offline', 'use only the local offline database (no network)')
  .option('--online', 'force live OSV.dev queries')
  .option('--strict-network', 'fail the scan on network errors instead of degrading gracefully')
  .option('--prod-only', 'ignore dev dependencies')
  .option('--ignore <ids...>', 'advisory ids to suppress')
  .option('--ignore-file <path>', 'path to a .npmscanignore file')
  .option('--cache-dir <dir>', 'override the cache directory')
  .option('--cache-ttl <hours>', 'cache freshness window in hours', (v) => Number(v))
  .option('--no-cache', 'bypass the on-disk cache')
  .option('--concurrency <n>', 'max concurrent OSV requests', (v) => Number(v))
  .action((path: string, opts: ScanCliOptions & { format: Format }) => runScan(path, opts));

const db = program.command('db').description('Manage the offline OSV database');
db.command('update')
  .description('Download or refresh the offline npm advisory database')
  .option('--cache-dir <dir>', 'override the cache directory')
  .option('--force', 'ignore conditional caching and re-download')
  .action((opts) => import('./commands/db.js').then((m) => m.runDbUpdate(opts)));
db.command('status')
  .description('Show offline database freshness')
  .option('--cache-dir <dir>', 'override the cache directory')
  .action((opts) => import('./commands/db.js').then((m) => m.runDbStatus(opts)));
db.command('path')
  .description('Print the offline database directory')
  .option('--cache-dir <dir>', 'override the cache directory')
  .action((opts) => import('./commands/db.js').then((m) => m.runDbPath(opts)));

program
  .command('report')
  .description('Re-render a saved JSON result into another format')
  .requiredOption('-i, --input <file>', 'path to a JSON scan result')
  .addOption(
    new Option('-f, --format <format>', 'output format')
      .choices(['table', 'json', 'sarif', 'html'])
      .default('html'),
  )
  .option('-o, --output <file>', 'write the report to a file instead of stdout')
  .action((opts) => runReport(opts));

program
  .command('serve')
  .description('Run a scan and open an interactive dashboard locally')
  .argument('[path]', 'project directory to scan', '.')
  .option('-i, --input <file>', 'serve a saved JSON result instead of scanning')
  .option('-p, --port <port>', 'port to listen on', (v) => Number(v), 7777)
  .option('--no-open', 'do not open the browser automatically')
  .option('--offline', 'use only the local offline database')
  .option('--online', 'force live OSV.dev queries')
  .action((path: string, opts) => runServe(path, opts));

program.parseAsync().catch((err) => {
  process.stderr.write(`npm-scanner: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 3;
});
