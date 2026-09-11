package com.gorunjinian.vaultovich

/*
 * Deciding whether a PSBT output belongs to this wallet.
 *
 * A signing device must decide which outputs are "ours" (change it can hide or summarize) and
 * which are payments it must show. The PSBT carries `PSBT_OUT_BIP32_DERIVATION` /
 * `PSBT_OUT_TAP_BIP32_DERIVATION` entries for that purpose, but they are written by the untrusted
 * host: a matching fingerprint proves nothing. The only sound test is to derive the key ourselves
 * from the account xpub we hold, rebuild the script the account would produce at that path, and
 * compare it byte-for-byte with the output's actual scriptPubKey. That is what the functions here
 * do; it is the same approach as Ledger's wallet policies and Trezor's change detection.
 */

/** A single-signature account this device controls, identified by its account-level xpub. */
data class SingleSigAccount(
    /** Fingerprint of the master key, as it appears in PSBT derivation entries. */
    val masterFingerprint: Long,
    /** Path from the master key to [accountKey], e.g. `m/84'/0'/0'`. */
    val accountPath: KeyPath,
    /** Public account key at [accountPath]. */
    val accountKey: DeterministicWallet.ExtendedPublicKey,
    /**
     * The script type this account watches. Explicit on purpose: an output paying our key with a
     * script type the wallet does not scan would be signable but invisible, i.e. lost.
     */
    val scriptType: ScriptType,
    /** Child branches that count as ours (BIP-44: 0 = receive, 1 = change). */
    val branches: Set<Long> = setOf(0L, 1L),
)

/** One participant of a multisig account: fingerprint plus the account xpub they contributed. */
data class Cosigner(
    val masterFingerprint: Long,
    val accountPath: KeyPath,
    val accountKey: DeterministicWallet.ExtendedPublicKey,
)

enum class MultisigScriptType { P2WSH, P2SH_P2WSH, P2SH }

/**
 * A k-of-n multisig account (BIP-48 style: every cosigner derives at the same `branch/index`).
 *
 * @param sortedKeys `true` for `sortedmulti` (BIP-67 ordering), `false` for `multi` in cosigner order.
 */
data class MultisigAccount(
    val threshold: Int,
    val cosigners: List<Cosigner>,
    val scriptType: MultisigScriptType,
    val sortedKeys: Boolean = true,
    val branches: Set<Long> = setOf(0L, 1L),
) {
    init {
        require(cosigners.size in 1..16) { "a multisig account needs 1 to 16 cosigners" }
        require(threshold in 1..cosigners.size) { "threshold must be between 1 and the number of cosigners" }
    }
}

sealed class OutputOwnership {
    /** The output script is exactly what the account produces at `branch/index`. */
    data class Ours(val branch: Long, val index: Long) : OutputOwnership() {
        val isChange: Boolean get() = branch == 1L
    }

    /** No derivation entry references the account: a payment to someone else. Show it. */
    data object External : OutputOwnership()

    /**
     * A derivation entry claims the account but the key or script does not check out. Treat as
     * hostile: show the output in full and never label it as change.
     */
    data class Mismatch(val reason: String) : OutputOwnership()
}

private data class Child(val branch: Long, val index: Long)

/** The `branch/index` suffix of [path] under [accountPath], or the reason it is not acceptable. */
private fun childOf(path: KeyPath, accountPath: KeyPath, branches: Set<Long>): Pair<Child?, String> {
    val prefix = accountPath.path
    return when {
        path.path.size != prefix.size + 2 -> null to "path depth is not account + 2"
        path.path.take(prefix.size) != prefix -> null to "path is not under the account"
        path.path[prefix.size] !in branches -> null to "branch ${path.path[prefix.size]} is not a receive or change branch"
        DeterministicWallet.isHardened(path.path[prefix.size + 1]) -> null to "hardened child index"
        else -> Child(path.path[prefix.size], path.path[prefix.size + 1]) to ""
    }
}

private fun scriptOf(elts: List<ScriptElt>): ByteVector = ByteVector(Script.write(elts))

/**
 * Decide whether output [outputIndex] belongs to [account].
 *
 * Every derivation entry carrying the account's fingerprint is checked: its path must be
 * `accountPath/branch/index`, the key must be what the account xpub derives there, and the output
 * script must equal the account's script for that key. The first entry that passes makes the
 * output [OutputOwnership.Ours]. Entries with other fingerprints are ignored.
 */
fun Psbt.verifyOutput(outputIndex: Int, account: SingleSigAccount): OutputOwnership {
    val output = outputs.getOrNull(outputIndex) ?: return OutputOwnership.Mismatch("no output at index $outputIndex")
    val script = global.tx.txOut[outputIndex].publicKeyScript
    val reasons = ArrayList<String>()

    if (account.scriptType == ScriptType.P2TR) {
        val claims = output.taprootDerivationPaths.filter { it.value.masterKeyFingerprint == account.masterFingerprint }
        if (claims.isEmpty()) return OutputOwnership.External
        for ((claimedKey, derivation) in claims) {
            val (child, why) = childOf(derivation.keyPath, account.accountPath, account.branches)
            if (child == null) { reasons += why; continue }
            if (derivation.leaves.isNotEmpty()) { reasons += "key is declared for script paths"; continue }
            val derived = runCatching { account.accountKey.derivePublicKey(listOf(child.branch, child.index)).publicKey.xOnly() }
                .getOrElse { reasons += "derivation failed"; continue }
            if (derived != claimedKey) { reasons += "declared key is not ours at ${child.branch}/${child.index}"; continue }
            // BIP-86: the output key is the internal key tweaked with no script tree.
            if (scriptOf(Script.pay2tr(derived, null as ByteVector32?)) != script) { reasons += "script is not our P2TR output at ${child.branch}/${child.index}"; continue }
            return OutputOwnership.Ours(child.branch, child.index)
        }
    } else {
        val claims = output.derivationPaths.filter { it.value.masterKeyFingerprint == account.masterFingerprint }
        if (claims.isEmpty()) return OutputOwnership.External
        for ((claimedKey, derivation) in claims) {
            val (child, why) = childOf(derivation.keyPath, account.accountPath, account.branches)
            if (child == null) { reasons += why; continue }
            val derived = runCatching { account.accountKey.derivePublicKey(listOf(child.branch, child.index)).publicKey }
                .getOrElse { reasons += "derivation failed"; continue }
            if (derived != claimedKey) { reasons += "declared key is not ours at ${child.branch}/${child.index}"; continue }
            val expected = when (account.scriptType) {
                ScriptType.P2WPKH -> Script.pay2wpkh(derived)
                ScriptType.P2PKH -> Script.pay2pkh(derived)
                ScriptType.P2SH_P2WPKH -> Script.pay2sh(Script.pay2wpkh(derived))
                ScriptType.P2TR -> error("unreachable")
            }
            if (scriptOf(expected) != script) { reasons += "script is not our ${account.scriptType} output at ${child.branch}/${child.index}"; continue }
            return OutputOwnership.Ours(child.branch, child.index)
        }
    }
    return OutputOwnership.Mismatch(reasons.joinToString("; "))
}

/**
 * Decide whether output [outputIndex] belongs to the multisig [account].
 *
 * The cosigners' keys are all rederived from the xpubs the device holds, so a host that swaps one
 * cosigner key for its own (turning a 2-of-3 we control into a 2-of-3 it controls) cannot pass:
 * the rebuilt script simply will not match. Derivation entries are used only to learn the
 * `branch/index`, which BIP-48 requires to be the same for every cosigner.
 */
fun Psbt.verifyOutput(outputIndex: Int, account: MultisigAccount): OutputOwnership {
    val output = outputs.getOrNull(outputIndex) ?: return OutputOwnership.Mismatch("no output at index $outputIndex")
    val script = global.tx.txOut[outputIndex].publicKeyScript

    val children = HashSet<Child>()
    var claimed = false
    for (cosigner in account.cosigners) {
        val claims = output.derivationPaths.values.filter { it.masterKeyFingerprint == cosigner.masterFingerprint }
        if (claims.isEmpty()) continue
        claimed = true
        val valid = claims.mapNotNull { childOf(it.keyPath, cosigner.accountPath, account.branches).first }
        if (valid.isEmpty()) return OutputOwnership.Mismatch("a cosigner's derivation path is not under its account")
        children += valid
    }
    if (!claimed) return OutputOwnership.External
    if (children.size != 1) return OutputOwnership.Mismatch("cosigners are not derived at a single branch/index")
    val child = children.single()

    val keys = account.cosigners.map { cosigner ->
        runCatching { cosigner.accountKey.derivePublicKey(listOf(child.branch, child.index)).publicKey }
            .getOrElse { return OutputOwnership.Mismatch("derivation failed") }
    }
    // BIP-67: sortedmulti orders the compressed keys lexicographically; equal-length hex sorts identically.
    val ordered = if (account.sortedKeys) keys.sortedBy { it.value.toHex() } else keys
    val multisig = Script.createMultiSigMofN(account.threshold, ordered)
    val expected = when (account.scriptType) {
        MultisigScriptType.P2WSH -> Script.pay2wsh(multisig)
        MultisigScriptType.P2SH_P2WSH -> Script.pay2sh(Script.pay2wsh(multisig))
        MultisigScriptType.P2SH -> Script.pay2sh(multisig)
    }
    return if (scriptOf(expected) == script) OutputOwnership.Ours(child.branch, child.index)
    else OutputOwnership.Mismatch("script is not our ${account.threshold}-of-${account.cosigners.size} ${account.scriptType} output at ${child.branch}/${child.index}")
}
