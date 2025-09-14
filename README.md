# VisuaLogin Core Engine

**A Secure, Deterministic, & Zero-Knowledge Password Generator**

VisuaLogin redefines digital security by replacing the need to memorize complex, abstract passwords with the natural human ability to remember visual patterns and spatial locations. This core engine empowers users to generate strong, unique passwords for every account using a combination of a domain name, username, a color, a pattern, and an optional geographic coordinate.

![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg) [![npm version](https://img.shields.io/npm/v/@visualogin/core)](https://www.npmjs.com/package/@visualogin/core)

## 🔍 The Problem: Password Fatigue is a Human Problem

Traditional password managers store your secrets, creating a valuable target for hackers. Remembering multiple complex passwords is difficult, leading to dangerous repetition. This problem is even more acute for individuals with dyslexia, learning disabilities, or anyone who struggles with textual memory.

## 🛡️ The VisuaLogin Solution: Security Through Instinct

Why force the brain to do what it's bad at (remembering `Tr0ub4d0r&3`), instead of leveraging what it's excellent at (recognizing patterns and remembering places)?

VisuaLogin uses a cryptographic one-way function to generate a password. Your visual choices are the **key** to the vault, but the vault itself is never stored anywhere—not on your device, not on our servers, **nowhere**. This is the principle of **Zero-Knowledge** access.

### How It Works

1.  **Visual Input:** For any login, you provide the domain (e.g., `github.com`), your username, a color from a palette, and a simple pattern drawn on a grid.
2.  **Optional Geospatial Lock:** For added security, you can optionally select a location on a map.
3.  **Cryptographic Generation:** This engine deterministically combines these inputs using modern cryptography (**Argon2id** and **HKDF**) to generate a strong, unique password that meets **NIST SP 800-63B** guidelines.
4.  **Result:** The same visual input on different domains produces completely different passwords. You never type or see your master password; you just *remember it visually*.

## ✨ Key Features

*   **🔒 Zero-Knowledge:** No passwords, patterns, or coordinates are ever stored or transmitted.
*   **🔄 Deterministic:** Your visual input always generates the same strong password for a given site and username.
*   **📜 NIST Compliant:** Generates passwords with enforced complexity rules (length, character variety, etc.).
*   **♿ Inclusive by Design:** Ideal for users with dyslexia, learning disabilities, or anyone who finds visual memory easier than textual memory.
*   **⚡ Future-Proof Cryptography:** Uses the winner of the Password Hashing Competition (Argon2id) to resist brute-force and GPU-based attacks.

---

## 🚀 Installation & Usage

The VisuaLogin core generator is available as a standalone npm package for integration into web apps, browser extensions, and other Node.js projects.

```bash
npm install @visualogin/core
```

### Basic Example

```javascript
// 1. Import the module
import PasswordGenerator from '@visualogin/core';

// 2. Define your visual secret input
const userVisualInput = {
  domain: "github.com",         // The website's domain
  username: "alice.dev",        // Your username for this site
  selectedColor: "#FF5733",     // A hex color you've chosen
  pattern: [15, 23, 41, 10, 39], // An array representing your drawn pattern
  coordinates: {                // Optional: A location you've chosen
    lat: 40.7128,
    lng: -74.0060
  }
};

// 3. Generate a password
try {
  const generatedPassword = await PasswordGenerator.generatePassword(userVisualInput, 18);
  console.log("Your secure password:", generatedPassword);
  // Example output: "7E&k7@W8-xyPq!vS4*L"
} catch (error) {
  console.error("Generation failed:", error.message);
}
```

### Advanced Example with Progress Tracking

```javascript
import PasswordGenerator from '@visualogin/core';

// Initialize and check environment support first
await PasswordGenerator.initialize();
const compatibility = PasswordGenerator.checkEnvironmentCompatibility();

if (!compatibility.supported) {
  throw new Error(`Unsupported browser: ${compatibility.errors.join(', ')}`);
}

const visualInput = {
  domain: "example.com",
  username: "john.doe",
  selectedColor: "#3399ff",
  pattern: [2, 4, 6, 8, 10] // Simpler pattern
};

// Generate with a progress callback for a UI progress bar
const password = await PasswordGenerator.generatePassword(
  visualInput,
  16, // Length of 16 characters
  (progress, message) => {
    // Update your application's UI here
    console.log(`[${Math.round(progress * 100)}%] ${message}`);
    // Example Logs:
    // [30%] Processing inputs
    // [60%] Running memory-hard encryption (this may take a few seconds)
    // [100%] Password generated successfully
  }
);
```

---

## 📚 API Reference

### `generatePassword(data, length, progressCallback)`

The core function for generating passwords. It combines user inputs using a cryptographically secure process (HKDF + Argon2id) to create a deterministic, strong password.

#### Parameters

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`data`** | `Object` | **Yes** | - | The visual input data object. |
| `data.domain` | `string` | **Yes** | - | The website's domain name (e.g., `"github.com"`). |
| `data.username` | `string` | **Yes** | - | The user's username for the specified domain. |
| `data.selectedColor` | `string` | **Yes** | - | A color selected from a palette, as a hex string (e.g., `"#FF5733"`). |
| `data.pattern` | `Array<number>` | **Yes** | - | An array of numbers representing a pattern drawn on a grid. |
| `data.coordinates` | `{ lat: number, lng: number }` | No | `{ lat: 0, lng: 0 }` | Optional geographic coordinates for added entropy. |
| **`length`** | `number` | No | `24` | The desired length of the generated password. Must be between `12` and `256`. |
| **`progressCallback`** | `Function` | No | - | A callback function `(progress: number, message: string) => void` for tracking the generation progress. `progress` is a number between `0` and `1`. |

#### Returns

`Promise<string>` - A promise that resolves to the generated password meeting NIST SP 800-63B complexity requirements.

#### Throws

- `Error` if the environment is not supported (e.g., missing Web Crypto API).
- `Error` if input validation fails (e.g., invalid color format, short domain).
- `Error` if the cryptographic operation fails for any reason.

---

### `checkEnvironmentCompatibility()`

Checks if the current environment (browser/Node.js) supports all required cryptographic APIs and features.

#### Returns

`Object` - A compatibility report object.
```javascript
{
  supported: true, // Boolean indicating overall compatibility
  errors: [],      // Array of critical error strings
  warnings: [],    // Array of non-critical warning strings
  features: {      // Detailed status of individual features
    webCrypto: true,
    textEncoder: true,
    argon2: true,
    // ...other features
  }
}
```

---

### `initialize()`

Initializes the library, primarily ensuring the Argon2 WebAssembly module is ready. It is recommended to call this once on app startup.

#### Returns

`Promise<boolean>` - A promise that resolves to `true` if initialization was successful.

---

### `validateInputData(data)`

A utility function to validate an input object before calling `generatePassword`. Useful for providing immediate user feedback in a UI.

#### Parameters

| Parameter | Type | Description |
| :--- | :--- | :--- |
| **`data`** | `Object` | The input data object to validate (same structure as for `generatePassword`). |

#### Returns

`Array<string>` - An array of validation error messages. An empty array means the input is valid.

**Example:**
```javascript
const errors = PasswordGenerator.utils.validateInputData(userInput);
if (errors.length > 0) {
  // Show errors to the user, e.g., "Please provide a valid hex color"
  displayErrorsToUser(errors);
}
```

---

## 👥 Who Is This For?

*   **👨‍💻 End Users:** Anyone looking for a more intuitive and secure way to manage online logins.
*   **🧑‍💻 Developers:** Those building privacy-focused applications, password managers, or secure authentication systems that need a reliable cryptographic password generator.
*   **👩‍🔬 Researchers:** Academics and students interested in cryptography, usability, and inclusive security design.

---

## 📜 License

The VisuaLogin Core Engine is free and open-source software licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**.

### What does this mean?

*   **✅ You can use, study, share, and modify** the software **for free** for any **personal, educational, or commercial** purpose.
*   **✅ You must** include the original copyright notice and license text in any distributed code.
*   **🔴 If you modify this software and run it as a hosted service (e.g., a web app, SaaS)**, you **must** make the **complete source code** of your modified version available to your users under this same license.

### Commercial Licensing

If the terms of the AGPLv3 are not suitable for your intended use—for instance, if you wish to create and distribute a proprietary derivative work **without** releasing its source code—a separate commercial license is available from the copyright holder (**VisuaLogin**).

**Please contact us at `visualogin@proton.me` to discuss your requirements and obtain a commercial license.**

---

*Copyright (c) 2025 VisuaLogin. Licensed under AGPLv3.*
