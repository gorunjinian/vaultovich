# Vaultovich

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A Kotlin/JVM Bitcoin library built for **offline signing**. It is the cryptographic core
extracted from [MetroVault](https://github.com/gorunjinian/MetroVault), an air-gapped
Android signing device, and is a fork of [ACINQ's bitcoin-kmp](https://github.com/ACINQ/bitcoin-kmp).

The library is deliberately small and fully auditable: no networking, no persistence, no
Android dependencies. It parses, derives, signs and serialises — nothing else.

## What's in it

| Area | Coverage |
|------|----------|
| Encoding | Base58 / Base58Check, Bech32 and Bech32m |
| Keys | BIP-32 deterministic wallets, BIP-39 mnemonics, BIP-44/48/49/84/86 derivation |
| Transactions | Parsing, creation, signing, verification; BIP-68/112 relative locktime; BIP-69 output ordering |
| Script | Full interpreter incl. OP_CLTV (BIP-65) / OP_CSV, P2PKH, P2SH (BIP-16), P2WPKH, P2WSH, P2TR |
| Signing | BIP-143 SegWit v0 sighash, BIP-341/342 Taproot sighash, BIP-340 Schnorr |
| PSBT | BIP-174 (v0), BIP-370 (v2), BIP-371 Taproot fields |
| Messages | BIP-137 ECDSA message signing, BIP-322 generic signed messages |
| Silent payments | BIP-352 send/receive/spend, BIP-374 DLEQ proofs, BIP-375 PSBT fields |
| Multisig | Output descriptors, MuSig2 key aggregation and nonce handling |

## Installation

```kotlin
dependencies {
    implementation("com.gorunjinian:vaultovich:0.1.0")

    // Required: a secp256k1 JNI binding for your platform.
    implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-android:0.24.0")  // Android
    // implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.24.0")   // Desktop JVM
}
```

Vaultovich exposes `fr.acinq.secp256k1:secp256k1-kmp` as an `api` dependency but does **not**
bundle a native binding — you pick the one matching your target, or you'll hit an
`UnsatisfiedLinkError` at first use.

The library is compiled to Java 17 bytecode and requires a JVM 17+ / Android API 26+ runtime.

## Usage

```kotlin
// Derive an address from a mnemonic
val seed = MnemonicCode.toSeed(mnemonic, passphrase = "")
val master = DeterministicWallet.generate(seed)
val account = DeterministicWallet.derivePrivateKey(master, KeyPath("m/84'/0'/0'"))
val address = Bitcoin.computeP2WpkhAddress(account.publicKey, Block.LivenetGenesisBlock.hash)

// Sign a PSBT. By default the signer refuses a segwit v0 input that lacks
// PSBT_IN_NON_WITNESS_UTXO (the BIP-143 fee attack) and any sighash type other than
// SIGHASH_ALL / SIGHASH_DEFAULT. Relax that only deliberately, via SignPolicy.
val psbt = Psbt.read(psbtBytes).right!!
val signed = psbt.sign(privateKey, inputIndex).right!!.psbt
val relaxed = psbt.sign(privateKey, inputIndex, SignPolicy(trustWitnessUtxo = true))

// Decide which outputs are ours (change) before showing a transaction. The script is rebuilt
// from the account xpub the device holds; a host-supplied fingerprint or path proves nothing.
val ours = SingleSigAccount(masterFingerprint, KeyPath("m/84'/0'/0'"), accountXpub, ScriptType.P2WPKH)
when (val o = psbt.verifyOutput(outputIndex, ours)) {
    is OutputOwnership.Ours -> if (o.isChange) hide() else showAsOurs()
    OutputOwnership.External -> showPayment()
    is OutputOwnership.Mismatch -> showPaymentAndWarn(o.reason)
}
```

## Building

```bash
./gradlew build     # compile + test
./gradlew test      # test only
```

Requires JDK 21 to build (the secp256k1 JNI test binding is published for JVM 21+), but
produces Java 17 bytecode.

## Relationship to bitcoin-kmp

Vaultovich narrows ACINQ's Kotlin Multiplatform library to a single Kotlin/JVM target and adds
the pieces an offline signer needs: BIP-322 message signing, BIP-352 silent payments, BIP-370
PSBT v2, BIP-374/375 DLEQ proofs and silent-payment PSBT fields, output descriptors, and
MuSig2. Two upstream PSBT fixes carried here have been submitted back to bitcoin-kmp.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Original work Copyright 2014 ACINQ SAS; modifications Copyright 2026 gorunjinian.
