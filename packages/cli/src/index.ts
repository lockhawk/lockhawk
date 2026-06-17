import { Command } from 'commander';

// Minimal entry point — commands are fully wired up in milestone M4.
const program = new Command();

program
  .name('npm-scanner')
  .description('Fast, free, accurate npm dependency vulnerability scanner')
  .version('0.1.0');

program
  .command('scan', { isDefault: true })
  .description('Scan a project for vulnerable dependencies')
  .argument('[path]', 'project directory to scan', '.')
  .action(() => {
    console.log('npm-scanner: scan command is being wired up (milestone M4).');
  });

program.parseAsync().catch((err) => {
  console.error(err);
  process.exitCode = 3;
});
