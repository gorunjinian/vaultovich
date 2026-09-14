package com.gorunjinian.vaultovich.crypto.musig2

import com.gorunjinian.vaultovich.ByteVector
import com.gorunjinian.vaultovich.Crypto
import com.gorunjinian.vaultovich.OutPoint
import com.gorunjinian.vaultovich.PrivateKey
import com.gorunjinian.vaultovich.Satoshi
import com.gorunjinian.vaultovich.Script
import com.gorunjinian.vaultovich.SigHash
import com.gorunjinian.vaultovich.Transaction
import com.gorunjinian.vaultovich.TxHash
import com.gorunjinian.vaultovich.TxIn
import com.gorunjinian.vaultovich.TxOut
import com.gorunjinian.vaultovich.utils.Either
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** A 2-of-2 MuSig2 taproot key-path spend end to end, and the single-use rule for secret nonces. */
class Musig2Test {

    private val k1 = PrivateKey(ByteVector(ByteArray(32) { 1 }))
    private val k2 = PrivateKey(ByteVector(ByteArray(32) { 2 }))
    private val pubs = listOf(k1.publicKey(), k2.publicKey())
    private val aggregated = Musig2.aggregateKeys(pubs)
    private val outputKey = aggregated.outputKey(Crypto.TaprootTweak.NoScriptTweak).first
    private val utxo = TxOut(Satoshi(100_000), ByteVector(Script.write(Script.pay2tr(outputKey))))
    private val tx = Transaction(
        2,
        listOf(TxIn(OutPoint(TxHash("cd".repeat(32)), 0), ByteVector.empty, TxIn.SEQUENCE_FINAL)),
        listOf(TxOut(Satoshi(90_000), ByteVector(Script.write(Script.pay2wpkh(k1.publicKey()))))),
        0,
    )

    private fun <T> right(e: Either<Throwable, T>): T = (e as? Either.Right)?.value ?: error("expected Right, got $e")

    @Test
    fun twoOfTwoKeyPathSpendVerifies() {
        val (secret1, public1) = Musig2.generateNonce(Either.Left(k1), pubs, null, null)
        val (secret2, public2) = Musig2.generateNonce(Either.Left(k2), pubs, null, null)
        val nonces = listOf(public1, public2)

        val partial1 = right(Musig2.signTaprootInput(k1, tx, 0, listOf(utxo), pubs, secret1, nonces, null))
        val partial2 = right(Musig2.signTaprootInput(k2, tx, 0, listOf(utxo), pubs, secret2, nonces, null))
        assertTrue(Musig2.verify(partial1, public1, k1.publicKey(), tx, 0, listOf(utxo), pubs, nonces, null))
        assertTrue(Musig2.verify(partial2, public2, k2.publicKey(), tx, 0, listOf(utxo), pubs, nonces, null))
        assertFalse(Musig2.verify(partial1, public2, k2.publicKey(), tx, 0, listOf(utxo), pubs, nonces, null))

        val sig = right(Musig2.aggregateTaprootSignatures(listOf(partial1, partial2), tx, 0, listOf(utxo), pubs, nonces, null))
        val digest = tx.hashForSigningTaprootKeyPath(0, listOf(utxo), SigHash.SIGHASH_DEFAULT)
        assertTrue(Crypto.verifySignatureSchnorr(digest, sig, outputKey))
    }

    @Test
    fun secretNonceIsSingleUse() {
        val (secret1, public1) = Musig2.generateNonce(Either.Left(k1), pubs, null, null)
        val (_, public2) = Musig2.generateNonce(Either.Left(k2), pubs, null, null)
        val nonces = listOf(public1, public2)
        assertFalse(secret1.isConsumed)
        right(Musig2.signTaprootInput(k1, tx, 0, listOf(utxo), pubs, secret1, nonces, null))
        assertTrue(secret1.isConsumed)
        // BIP-327: "The Sign algorithm must not be executed twice with the same secnonce."
        val e = runCatching { Musig2.signTaprootInput(k1, tx, 0, listOf(utxo), pubs, secret1, nonces, null) }.exceptionOrNull()
        assertTrue("expected IllegalStateException, got $e", e is IllegalStateException)
        assertEquals("<secret_nonce>", secret1.toString())
    }

    @Test
    fun randomSessionIdsProduceDistinctNonces() {
        val (_, a) = Musig2.generateNonce(Either.Left(k1), pubs, null, null)
        val (_, b) = Musig2.generateNonce(Either.Left(k1), pubs, null, null)
        assertNotEquals(a, b)
    }
}
