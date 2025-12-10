import { generateDeterministicPair, verifyPassword, enableDebug } from '../src/gun-authd.js';

/**
 * Unit tests for gun-authd
 * Run with: node test/unit.test.js
 */

const COLORS = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  reset: '\x1b[0m'
};

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`${COLORS.green}✓${COLORS.reset} ${message}`);
    passed++;
  } else {
    console.log(`${COLORS.red}✗${COLORS.reset} ${message}`);
    failed++;
  }
}

async function runTests() {
  console.log('\n🧪 gun-authd Unit Tests\n');
  console.log('='.repeat(50));

  // Test 1: Determinism - same input = same output
  console.log('\n📋 Test: Determinism\n');
  
  const pair1 = await generateDeterministicPair("alice", "password123!");
  const pair2 = await generateDeterministicPair("alice", "password123!");
  
  assert(pair1.pub === pair2.pub, "Same username/password produces same pub key");
  assert(pair1.priv === pair2.priv, "Same username/password produces same priv key");
  assert(pair1.epub === pair2.epub, "Same username/password produces same epub key");
  assert(pair1.epriv === pair2.epriv, "Same username/password produces same epriv key");

  // Test 2: Different inputs = different outputs
  console.log('\n📋 Test: Uniqueness\n');
  
  const pair3 = await generateDeterministicPair("bob", "password123!");
  const pair4 = await generateDeterministicPair("alice", "differentPassword!");
  
  assert(pair1.pub !== pair3.pub, "Different username produces different key");
  assert(pair1.pub !== pair4.pub, "Different password produces different key");

  // Test 3: Key format validation
  console.log('\n📋 Test: Key Format\n');
  
  assert(typeof pair1.pub === 'string', "pub is a string");
  assert(pair1.pub.includes('.'), "pub has x.y format");
  assert(typeof pair1.priv === 'string', "priv is a string");
  assert(typeof pair1.epub === 'string', "epub is a string");
  assert(pair1.epub.includes('.'), "epub has x.y format");
  assert(typeof pair1.epriv === 'string', "epriv is a string");

  // Test 4: Domain separation (signing key != encryption key)
  console.log('\n📋 Test: Domain Separation\n');
  
  assert(pair1.pub !== pair1.epub, "Signing pub != Encryption pub");
  assert(pair1.priv !== pair1.epriv, "Signing priv != Encryption priv");

  // Test 5: Verify password function
  console.log('\n📋 Test: Password Verification\n');
  
  const isValid = await verifyPassword(pair1.pub, "alice", "password123!");
  const isInvalid = await verifyPassword(pair1.pub, "alice", "wrongPassword!");
  
  assert(isValid === true, "Correct password returns true");
  assert(isInvalid === false, "Wrong password returns false");

  // Test 6: Normalization
  console.log('\n📋 Test: String Normalization\n');
  
  const pairNormal = await generateDeterministicPair("alice", "password");
  const pairSpaces = await generateDeterministicPair("  alice  ", "  password  ");
  
  assert(pairNormal.pub === pairSpaces.pub, "Whitespace is trimmed correctly");

  // Test 7: Unicode normalization
  console.log('\n📋 Test: Unicode Normalization\n');
  
  const pairUnicode1 = await generateDeterministicPair("café", "password!");
  const pairUnicode2 = await generateDeterministicPair("café", "password!"); // may differ in NFC
  
  assert(pairUnicode1.pub === pairUnicode2.pub, "Unicode strings are normalized (NFC)");

  // Test 8: Empty/invalid inputs
  console.log('\n📋 Test: Edge Cases\n');
  
  let emptyError = false;
  try {
    await generateDeterministicPair("", "password!");
  } catch (e) {
    emptyError = true;
  }
  // Note: empty username is allowed but produces deterministic keys
  // We don't throw an error for empty username
  
  const pairEmpty = await generateDeterministicPair("", "password!");
  assert(typeof pairEmpty.pub === 'string', "Empty username still produces valid pair");

  // Print results
  console.log('\n' + '='.repeat(50));
  console.log(`\n📊 Results: ${COLORS.green}${passed} passed${COLORS.reset}, ${COLORS.red}${failed} failed${COLORS.reset}\n`);
  
  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(e => {
  console.error('Test error:', e);
  process.exit(1);
});
