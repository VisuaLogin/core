#!/usr/bin/env node

/**
 * 🆘 VisuaLogin Emergency Password Recovery Tool
 * 
 * Use this tool only when other front-end access points are unavailable.
 * This CLI tool recreates your password using the same cryptographic process.
 * 
 * SECURITY WARNING: 
 * - Be aware of your surroundings when entering sensitive information
 * - Ensure no one is looking over your shoulder
 * - Clear your terminal history after use if on a shared machine
 */

import readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';
import PasswordGenerator from './src/visualogin-core.js';

// Create readline interface for user input
const rl = readline.createInterface({ input, output });

function clearScreen() {
  console.clear();
  console.log('==========================================');
  console.log('🆘 VISUALOGIN EMERGENCY RECOVERY TOOL');
  console.log('==========================================\n');
}

async function askQuestion(question, maskInput = false) {
  if (maskInput) {
    // For sensitive input, we need to use a different approach
    const rlSync = readline.createInterface({
      input,
      output,
      terminal: true
    });
    
    return new Promise((resolve) => {
      rlSync.question(question, { hideEchoBack: true }, (answer) => {
        rlSync.close();
        resolve(answer);
      });
    });
  }
  return rl.question(question);
}

async function validateAndRetry(question, validator, errorMessage, maskInput = false) {
  while (true) {
    const answer = maskInput ? await askQuestion(question, true) : await askQuestion(question);
    if (validator(answer)) {
      return answer;
    }
    console.log(`❌ ${errorMessage}\n`);
  }
}

function validateHexColor(color) {
  return /^#([0-9A-F]{3}){1,2}$/i.test(color);
}

function validatePattern(pattern) {
  const points = pattern.split(',').map(p => p.trim());
  return points.length >= 4 && points.every(p => !isNaN(p) && p !== '');
}

function validateDomain(domain) {
  return domain.length >= 3 && domain.includes('.');
}

function validateUsername(username) {
  return username.length >= 2;
}

function validateCoordinate(coord, isLatitude = true) {
  const num = parseFloat(coord);
  if (isNaN(num)) return false;
  if (isLatitude) return num >= -90 && num <= 90;
  return num >= -180 && num <= 180;
}

async function runRecovery() {
  try {
    clearScreen();
    
    console.log('🔐 Please provide your visual login details exactly as you remember them:\n');

    // Collect all required information
    const domain = await validateAndRetry(
      '1. Enter the website domain (e.g., "github.com"): ',
      validateDomain,
      'Please enter a valid domain name (e.g., github.com)'
    );

    const username = await validateAndRetry(
      '2. Enter your username for this site: ',
      validateUsername,
      'Username must be at least 2 characters long'
    );

    const selectedColor = await validateAndRetry(
      '3. Enter your hex color (e.g., "#FF5733"): ',
      validateHexColor,
      'Please enter a valid hex color (e.g., #FF5733)'
    );

    const pattern = await validateAndRetry(
      '4. Enter your pattern numbers, separated by commas (e.g., "10,20,30,40"): ',
      validatePattern,
      'Pattern must contain at least 4 numbers separated by commas'
    );

    console.log('\n5. Geographic coordinates (optional - press Enter to skip)');
    const useCoordinates = (await askQuestion('   Did you use coordinates? (y/N): ')).toLowerCase() === 'y';

    let coordinates = { lat: 0, lng: 0 };
    if (useCoordinates) {
      const lat = await validateAndRetry(
        '   Enter latitude (-90 to 90): ',
        coord => validateCoordinate(coord, true),
        'Please enter a valid latitude between -90 and 90'
      );

      const lng = await validateAndRetry(
        '   Enter longitude (-180 to 180): ',
        coord => validateCoordinate(coord, false),
        'Please enter a valid longitude between -180 and 180'
      );

      coordinates = { lat: parseFloat(lat), lng: parseFloat(lng) };
    }

    const passwordLength = await validateAndRetry(
      '6. Password length (12-64, default 24): ',
      len => len === '' || (!isNaN(len) && len >= 12 && len <= 64),
      'Please enter a number between 12 and 64',
      false
    );

    // Prepare input data
    const inputData = {
      domain: domain.trim(),
      username: username.trim(),
      selectedColor: selectedColor.trim().toUpperCase(),
      pattern: pattern.split(',').map(p => parseInt(p.trim())),
      coordinates
    };

    const length = passwordLength ? parseInt(passwordLength) : 24;

    clearScreen();
    console.log('🔄 Initializing cryptographic engine...\n');

    // Initialize and generate
    await PasswordGenerator.initialize();
    
    console.log('⚡ Generating your password...');
    console.log('   This may take a few seconds due to memory-hard encryption\n');

    const password = await PasswordGenerator.generatePassword(
      inputData,
      length,
      (progress, message) => {
        const percent = Math.round(progress * 100);
        process.stdout.write(`\r📊 ${percent}% - ${message}`);
        if (percent === 100) process.stdout.write('\n\n');
      }
    );

    // Display results securely
    clearScreen();
    console.log('✅ PASSWORD RECOVERY SUCCESSFUL\n');
    console.log('==========================================');
    console.log('🔑 YOUR GENERATED PASSWORD:');
    console.log('==========================================');
    console.log(password);
    console.log('==========================================\n');

    console.log('📋 Input Summary:');
    console.log(`   Domain: ${domain}`);
    console.log(`   Username: ${username}`);
    console.log(`   Color: ${selectedColor}`);
    console.log(`   Pattern: [${inputData.pattern.join(', ')}]`);
    if (useCoordinates) {
      console.log(`   Coordinates: ${coordinates.lat}, ${coordinates.lng}`);
    }
    console.log(`   Length: ${length} characters\n`);

    console.log('⚠️  SECURITY NOTICE:');
    console.log('   - Use this password immediately to access your account');
    console.log('   - Consider changing your recovery options after login');
    console.log('   - Clear terminal history if on shared computer');
    console.log('   - Close this terminal when finished\n');

  } catch (error) {
    console.error('\n❌ RECOVERY FAILED:');
    console.error(`   ${error.message}`);
    console.log('\n💡 TROUBLESHOOTING:');
    console.log('   - Double-check all input values for accuracy');
    console.log('   - Ensure you\'re using the exact same visual inputs');
    console.log('   - Try again with precise values\n');
    
  } finally {
    rl.close();
    // Small delay to ensure user sees the output
    setTimeout(() => process.exit(0), 100);
  }
}

// Handle CTRL+C gracefully
rl.on('SIGINT', () => {
  console.log('\n\n⚠️  Recovery cancelled by user');
  rl.close();
  process.exit(0);
});

// Run recovery if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runRecovery();
}

export { runRecovery };
