package com.gorunjinian.vaultovich.silentpayments

import com.gorunjinian.vaultovich.ByteVector
import com.gorunjinian.vaultovich.ByteVector32
import com.gorunjinian.vaultovich.Crypto
import com.gorunjinian.vaultovich.LexicographicalOrdering
import com.gorunjinian.vaultovich.OutPoint
import com.gorunjinian.vaultovich.PrivateKey
import com.gorunjinian.vaultovich.PublicKey
import com.gorunjinian.vaultovich.Script
import com.gorunjinian.vaultovich.OP_PUSHDATA
import com.gorunjinian.vaultovich.XonlyPublicKey
import com.gorunjinian.vaultovich.silentpayments.SilentPaymentInputs.SpInputKind
import java.math.BigInteger

/**
 * BIP-352 Silent Payments — **sender-side** protocol primitives.
 *
 * This module only contains the math a sender needs to pay to one or more `sp1q…` recipients:
 * summing the spent input private keys, deriving `input_hash`, the ECDH shared secret, and the
 * per-output taproot key `P_k`. There is deliberately **no** label tweak, no receiver scanning,
 * and nothing that implies holding scan/spend keys or scanning the chain — those belong to the
 * watching wallet.
 *
 * The wire/byte conventions mirror drongo (`SilentPaymentUtils.java`) so MetroVault is
 * interop-compatible with Sparrow out of the gate.
 */
object SilentPayments {
    const val BIP0352_INPUTS_TAG: String = "BIP0352/Inputs"
    const val BIP0352_SHARED_SECRET_TAG: String = "BIP0352/SharedSecret"

    /** Maximum number of recipients sharing one scan key (per BIP-352). */
    const val K_MAX: Int = 2323

    /** The secp256k1 group order n. */
    private val CURVE_N: BigInteger = BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

    /** Reason a sender-side derivation failed; carried by [SilentPaymentMathException]. */
    enum class FailureReason {
        NO_ELIGIBLE_INPUTS, NO_RECIPIENTS, PRIVATE_KEY_SUM_ZERO, INVALID_INPUT_HASH, INVALID_TWEAK, GROUP_EXCEEDS_KMAX,
        /** The private key supplied for an input does not reproduce that input's scriptPubKey. */
        KEY_DOES_NOT_MATCH_INPUT
    }

    /**
     * Typed failure from the BIP-352 sender math. Extends [IllegalArgumentException] so callers that
     * only care that "the math rejected this" can still catch the broad type, while orchestrators
     * (the sender service) can map [reason] to a user-facing error.
     */
    class SilentPaymentMathException(val reason: FailureReason, message: String) : IllegalArgumentException(message)

    /**
     * A spent input whose private key participates in the shared-secret derivation.
     *
     * For a taproot input this must be the private key of the taproot *output* key (BIP-352: "the
     * sender uses the private key corresponding to the taproot output key (i.e. the tweaked private
     * key)"), not the BIP-86 internal key. Prefer building these through [eligibleKey], which checks
     * the key against the script being spent; see [taprootOutputPrivateKey] for the tweak.
     */
    data class EligibleInputKey(val privateKey: PrivateKey, val isTaproot: Boolean)

    /**
     * An input the sender is spending: the key we hold for it and the script it pays to, so the
     * key can be checked against the script and the input classified per BIP-352.
     *
     * @param privateKey for P2TR the output-key private key ([taprootOutputPrivateKey]); otherwise the key whose hash the script commits to.
     * @param redeemScript the P2SH redeem script for P2SH-P2WPKH inputs.
     * @param witnessStack the witness, if the input is already signed (used to detect NUMS script-path spends).
     */
    data class SpentInput(
        val outPoint: OutPoint,
        val privateKey: PrivateKey,
        val scriptPubKey: ByteVector,
        val redeemScript: ByteVector? = null,
        val witnessStack: List<ByteVector>? = null,
    )

    /**
     * The private key of a BIP-341 taproot *output* key, from the internal key and optional script
     * tree root: `t = H_TapTweak(P || root)`, `d = k + t` after negating `k` if `P` has odd Y. This
     * is what BIP-352 requires as the input key of a P2TR input.
     */
    fun taprootOutputPrivateKey(internalKey: PrivateKey, merkleRoot: ByteVector32? = null): PrivateKey {
        val tweak = if (merkleRoot == null) Crypto.TaprootTweak.NoScriptTweak else Crypto.TaprootTweak.ScriptTweak(merkleRoot)
        return internalKey.tweak(internalKey.xOnlyPublicKey().tweak(tweak))
    }

    /**
     * Classify a spent input and check that [SpentInput.privateKey] is the key its script commits to.
     *
     * Returns `null` when the input must be left out of the shared-secret sum: a script type BIP-352
     * does not cover, a taproot script-path spend with the NUMS internal key, or a P2PKH / P2WPKH /
     * P2SH-P2WPKH input whose key hash was computed over the *uncompressed* encoding, which BIP-352
     * receivers skip ("only X-only and compressed public keys are permitted").
     *
     * @throws SilentPaymentMathException with [FailureReason.KEY_DOES_NOT_MATCH_INPUT] when the key
     * reproduces neither encoding: a payment derived from it would be unrecoverable by the receiver.
     */
    fun eligibleKey(input: SpentInput): EligibleInputKey? {
        val pub = input.privateKey.publicKey()
        fun mismatch(kind: String): Nothing = throw SilentPaymentMathException(
            FailureReason.KEY_DOES_NOT_MATCH_INPUT, "the private key does not match the $kind input being spent"
        )
        /** true: compressed key matches; false: only the uncompressed key matches (skip); throws otherwise. */
        fun compressedKeyMatches(hash: ByteVector, kind: String): Boolean = when {
            hash == ByteVector(pub.hash160()) -> true
            hash == ByteVector(Crypto.hash160(pub.toUncompressedBin())) -> false
            else -> mismatch(kind)
        }
        fun push(script: ByteVector, index: Int): ByteVector = (Script.parse(script)[index] as OP_PUSHDATA).data

        return when (SilentPaymentInputs.classify(input.scriptPubKey, input.redeemScript, input.witnessStack)) {
            SpInputKind.INELIGIBLE -> null
            SpInputKind.P2TR -> {
                val outputKey = Script.pay2trOutputKey(input.scriptPubKey) ?: mismatch("P2TR")
                if (input.privateKey.xOnlyPublicKey() != outputKey) mismatch("P2TR (the output-key private key is required, see taprootOutputPrivateKey)")
                EligibleInputKey(input.privateKey, isTaproot = true)
            }
            SpInputKind.P2WPKH ->
                if (compressedKeyMatches(push(input.scriptPubKey, 1), "P2WPKH")) EligibleInputKey(input.privateKey, isTaproot = false) else null
            SpInputKind.P2SH_P2WPKH -> {
                val redeem = input.redeemScript ?: mismatch("P2SH-P2WPKH")
                if (ByteVector(Script.write(Script.pay2sh(redeem.toByteArray()))) != input.scriptPubKey) mismatch("P2SH-P2WPKH (redeem script)")
                if (compressedKeyMatches(push(redeem, 1), "P2SH-P2WPKH")) EligibleInputKey(input.privateKey, isTaproot = false) else null
            }
            SpInputKind.P2PKH ->
                if (compressedKeyMatches(push(input.scriptPubKey, 2), "P2PKH")) EligibleInputKey(input.privateKey, isTaproot = false) else null
        }
    }

    /** [eligibleKey] over every input, dropping the ineligible ones. */
    fun eligibleKeys(inputs: List<SpentInput>): List<EligibleInputKey> = inputs.mapNotNull { eligibleKey(it) }

    /**
     * The BIP-375 ECDH share for one scan key: `a · B_scan`, the raw point without the
     * `input_hash` factor (the verifier applies it). Pair it with a BIP-374 proof from
     * [DleqProof.generate] using the same `a` and `B_scan`.
     */
    fun ecdhShare(sumPrivateKey: PrivateKey, scanPubKey: PublicKey): PublicKey = scanPubKey * sumPrivateKey

    /** The public scan/spend keys of a single silent-payment recipient. */
    data class RecipientKeys(val scanPubKey: PublicKey, val spendPubKey: PublicKey)

    /** A derived taproot output key, paired with the index of the recipient it belongs to. */
    data class DerivedOutput(val recipientIndex: Int, val outputKey: XonlyPublicKey)

    /**
     * Sum the eligible input private keys into the scalar `a`, applying BIP-340 even-Y negation
     * to taproot keys (per BIP-352 §"Inputs For Shared Secret Derivation").
     *
     * Uses modular arithmetic over n so that an intermediate sum of zero (with a non-zero final
     * sum — the BIP-352 v1.1.1 edge case) does not fail. Fails only if the **final** sum is zero.
     */
    fun summedPrivateKey(keys: List<EligibleInputKey>): PrivateKey {
        if (keys.isEmpty()) throw SilentPaymentMathException(
            FailureReason.NO_ELIGIBLE_INPUTS, "no eligible inputs to derive a silent payments shared secret"
        )
        var sum = BigInteger.ZERO
        for (k in keys) {
            var x = BigInteger(1, k.privateKey.value.toByteArray())
            if (k.isTaproot && k.privateKey.publicKey().isOdd()) {
                x = CURVE_N.subtract(x).mod(CURVE_N)
            }
            sum = sum.add(x).mod(CURVE_N)
        }
        if (sum.signum() == 0) throw SilentPaymentMathException(
            FailureReason.PRIVATE_KEY_SUM_ZERO, "the summed private key is zero for the eligible silent payments inputs"
        )
        return PrivateKey(scalarTo32(sum))
    }

    /**
     * Find the lexicographically smallest outpoint by its **serialized** bytes
     * (`txid` little-endian ‖ `vout` little-endian uint32), per BIP-352. This is *not* the same
     * as ordering by display-order txid then index, so we compare the serialized form directly.
     */
    fun smallestOutpoint(outPoints: List<OutPoint>): OutPoint {
        require(outPoints.isNotEmpty()) { "no outpoints provided to calculate silent payments input hash" }
        return outPoints.reduce { a, b ->
            if (LexicographicalOrdering.isLessThan(OutPoint.write(b), OutPoint.write(a))) b else a
        }
    }

    /**
     * `input_hash = taggedHash(serialize(outpoint_L) ‖ ser_P(A), "BIP0352/Inputs")`.
     *
     * @throws IllegalArgumentException if the result is zero or ≥ n (an invalid scalar).
     */
    fun inputHash(smallestOutpoint: OutPoint, sumPublicKey: PublicKey): ByteVector32 {
        val data = OutPoint.write(smallestOutpoint) + sumPublicKey.value.toByteArray()
        val hash = Crypto.taggedHash(data, BIP0352_INPUTS_TAG)
        if (!Crypto.isPrivKeyValid(hash.toByteArray())) throw SilentPaymentMathException(
            FailureReason.INVALID_INPUT_HASH, "the input hash is invalid for the eligible silent payments inputs"
        )
        return hash
    }

    /**
     * `ecdh_shared_secret = input_hash · a · B_scan`.
     *
     * Implemented as `B_scan · (input_hash · a)`; scalar multiplication is commutative so this
     * equals drongo's `(a · B_scan) · input_hash`.
     */
    fun sharedSecret(inputHash: ByteVector32, sumPrivateKey: PrivateKey, scanPubKey: PublicKey): PublicKey {
        val scalar = PrivateKey(inputHash) * sumPrivateKey
        return scanPubKey * scalar
    }

    /**
     * Derive the taproot output key for the `k`-th output sharing this [sharedSecret]:
     *
     * `t_k = taggedHash(ser_P(sharedSecret) ‖ ser_32(k), "BIP0352/SharedSecret")`,
     * `P_k = B_spend + t_k·G`, returned as the X-only key (the P2TR output key, no taptweak).
     *
     * @param k output index within the scan-key group; encoded big-endian per BIP-352 `ser_32`.
     * @throws IllegalArgumentException if `t_k` is zero or ≥ n.
     */
    fun outputKey(spendPubKey: PublicKey, sharedSecret: PublicKey, k: Int): XonlyPublicKey {
        val data = sharedSecret.value.toByteArray() + ser32BE(k)
        val tk = Crypto.taggedHash(data, BIP0352_SHARED_SECRET_TAG)
        if (!Crypto.isPrivKeyValid(tk.toByteArray())) throw SilentPaymentMathException(
            FailureReason.INVALID_TWEAK, "the tk value is invalid for the eligible silent payments inputs"
        )
        val pk = spendPubKey + PrivateKey(tk).publicKey()
        return pk.xOnly()
    }

    /**
     * Sender derivation from the raw inputs: every input is classified and its key checked against
     * its script ([eligibleKey]); the smallest outpoint is taken over *all* inputs, eligible or not,
     * as BIP-352 requires.
     */
    fun deriveOutputs(inputs: List<SpentInput>, recipients: List<RecipientKeys>): List<DerivedOutput> =
        deriveOutputs(eligibleKeys(inputs), inputs.map { it.outPoint }, recipients)

    /**
     * All-in-one sender derivation: from the eligible spent keys, the full set of outpoints, and
     * the recipients, produce a taproot output key for every recipient.
     *
     * Recipients are grouped by scan key (groups in first-seen order). Within a group `k` starts at
     * 0 and follows BIP-375's rule for PSBTs: "if there are multiple silent payment codes with the
     * same scan key, sort the codes lexicographically in ascending order to determine the ordering
     * of the k value", i.e. ascending spend key bytes, with repeated codes kept in output order
     * (stable sort). Results are tagged with the original recipient index so the caller can splice
     * each derived output back into the right slot.
     */
    fun deriveOutputs(
        eligibleKeys: List<EligibleInputKey>,
        allOutpoints: List<OutPoint>,
        recipients: List<RecipientKeys>
    ): List<DerivedOutput> {
        if (recipients.isEmpty()) throw SilentPaymentMathException(
            FailureReason.NO_RECIPIENTS, "no silent payment recipients"
        )
        val a = summedPrivateKey(eligibleKeys)
        val sumPublicKey = a.publicKey()
        val outpointL = smallestOutpoint(allOutpoints)
        val hash = inputHash(outpointL, sumPublicKey)

        // Group recipient indices by scan key, preserving insertion order.
        val groups = LinkedHashMap<ByteVector, MutableList<Int>>()
        recipients.forEachIndexed { index, recipient ->
            groups.getOrPut(recipient.scanPubKey.value) { mutableListOf() }.add(index)
        }

        val results = ArrayList<DerivedOutput>(recipients.size)
        for ((_, indices) in groups) {
            if (indices.size > K_MAX) throw SilentPaymentMathException(
                FailureReason.GROUP_EXCEEDS_KMAX, "silent payment recipient group exceeds K_MAX ($K_MAX)"
            )
            val scanPubKey = recipients[indices.first()].scanPubKey
            val secret = sharedSecret(hash, a, scanPubKey)
            val ordered = indices.sortedWith { i, j -> compareUnsigned(recipients[i].spendPubKey.value, recipients[j].spendPubKey.value) }
            ordered.forEachIndexed { k, recipientIndex ->
                val key = outputKey(recipients[recipientIndex].spendPubKey, secret, k)
                results.add(DerivedOutput(recipientIndex, key))
            }
        }
        return results
    }

    /** Unsigned lexicographic byte-string comparison (what "lexicographically" means for serialized codes). */
    private fun compareUnsigned(a: ByteVector, b: ByteVector): Int {
        val n = minOf(a.size(), b.size())
        for (i in 0 until n) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return a.size() - b.size()
    }

    /** Big-endian uint32 serialization (BIP-352 `ser_32`). */
    private fun ser32BE(k: Int): ByteArray = byteArrayOf(
        (k ushr 24).toByte(),
        (k ushr 16).toByte(),
        (k ushr 8).toByte(),
        k.toByte()
    )

    /** Encode a scalar in [0, n) as a fixed 32-byte big-endian array. */
    private fun scalarTo32(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        return when {
            bytes.size == 32 -> bytes
            bytes.size == 33 && bytes[0] == 0.toByte() -> bytes.copyOfRange(1, 33)
            bytes.size < 32 -> ByteArray(32 - bytes.size) + bytes
            else -> error("scalar does not fit in 32 bytes")
        }
    }
}
