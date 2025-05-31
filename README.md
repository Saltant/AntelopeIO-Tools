# AntelopeIO Signature Verification Library

![.NET Version](https://img.shields.io/badge/.NET-9.0-blue)
[![NuGet Package](https://img.shields.io/nuget/v/Saltant.AntelopeIO.Tools)](https://www.nuget.org/packages/Saltant.AntelopeIO.Tools)
![License](https://img.shields.io/badge/license-GPL--3.0-green)

Provides functionality to verify cryptographic signatures for AntelopeIO-based blockchain transactions.
Supports both K1 (secp256k1) and WA (WebAuthn/secp256r1) signature schemes.

## Installation

```bash
dotnet add package Saltant.AntelopeIO.Tools
```

## Quick Start

1. Initialize the verifier:
```csharp
// Initialize with chain-specific options
var options = new SignatureVerifierOptions
{
    ChainId = "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906",
    IsDebug = false
};

var verifier = new SignatureVerifier(options);
```
2. Verify signatures:
```csharp
try 
{
    bool isValid = verifier.VerifySignature(transaction, candidateKeys);
    Console.WriteLine($"Verification result: {isValid}");
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex.Message}");
}
```
## Complete Usage Example
```csharp
// 1. Prepare transaction data
var transaction = new TransactionResult
{
    Signature = "SIG_K1_KhyBkPjQ3aM7h5gU5jGKZJr7B8JdJtI3ZrWbY7LmJ5J5vHJ5J5",
    SignedTransaction = new Transaction
    {
        // Transaction details...
    }
};

// 2. Provide candidate public keys
var candidateKeys = new[]
{
    "PUB_K1_6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5BoDq63",
    "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
};

// 3. Verify signature
try 
{
    bool isValid = verifier.VerifySignature(transaction, candidateKeys);
    Console.WriteLine($"Verification result: {isValid}");
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex.Message}");
}
```
## Features

- **Supported Signature Types**:
  - SIG_K1_ (secp256k1)
  - SIG_WA_ (WebAuthn/secp256r1)

- **Debug Mode** provides:
  - Raw signature bytes
  - Recovered public keys
  - Intermediate hash values
  - WebAuthn validation details

## Chain Compatibility

Tested with:
- XPR Network
- WAX
- Telos
- Antelope/Leap chains

## License

Distributed under the GPL-3.0 License. See [LICENSE](LICENSE) for full terms.

---

**Important Notes**:
- Always use the correct ChainId for your target network
- Disable debug mode in production
- Implement proper exception handling
