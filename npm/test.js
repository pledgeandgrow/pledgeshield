const { scan } = require('./index.js');

async function main() {
  const report = await scan({ format: 'json' });
  console.log(report);
}

main().catch(console.error);
