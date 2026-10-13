// Emits ephemeral synthetic key material to stdout for isolated native tests.
// Redirect only to a temporary directory; never commit or upload the output.
import { createNativeHpkeCases } from './helpers/native-hpke-cases.mjs';

const args = process.argv.slice(2);
if (args.length > 1 || args.length === 1 && args[0] !== '--tsv') {
  throw new Error('Usage: node emit-native-hpke.mjs [--tsv]');
}
const corpus = await createNativeHpkeCases();
if (args[0] === '--tsv') {
  const fields = ['name', 'profile', 'recipient_private_hex', 'recipient_public_hex',
    'enc_hex', 'info_hex', 'aad_hex', 'ciphertext_hex', 'plaintext_hex'];
  process.stdout.write(corpus.cases.map(row => fields.map(field => row[field]).join('\t')).join('\n') + '\n');
} else process.stdout.write(JSON.stringify(corpus) + '\n');
