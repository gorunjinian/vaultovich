package com.gorunjinian.vaultovich.silentpayments

import com.gorunjinian.vaultovich.ByteVector
import com.gorunjinian.vaultovich.ByteVector32
import com.gorunjinian.vaultovich.Crypto
import com.gorunjinian.vaultovich.DataEntry
import com.gorunjinian.vaultovich.DeterministicWallet
import com.gorunjinian.vaultovich.Global
import com.gorunjinian.vaultovich.Input
import com.gorunjinian.vaultovich.KeyPath
import com.gorunjinian.vaultovich.OP_2
import com.gorunjinian.vaultovich.OP_PUSHDATA
import com.gorunjinian.vaultovich.OutPoint
import com.gorunjinian.vaultovich.Output
import com.gorunjinian.vaultovich.PrivateKey
import com.gorunjinian.vaultovich.Psbt
import com.gorunjinian.vaultovich.PublicKey
import com.gorunjinian.vaultovich.Satoshi
import com.gorunjinian.vaultovich.Script
import com.gorunjinian.vaultovich.ScriptElt
import com.gorunjinian.vaultovich.ScriptTree
import com.gorunjinian.vaultovich.SigHash
import com.gorunjinian.vaultovich.SignPolicy
import com.gorunjinian.vaultovich.Transaction
import com.gorunjinian.vaultovich.TxHash
import com.gorunjinian.vaultovich.TxIn
import com.gorunjinian.vaultovich.TxOut
import com.gorunjinian.vaultovich.UpdateFailure
import com.gorunjinian.vaultovich.silentpayments.SilentPayments.FailureReason
import com.gorunjinian.vaultovich.silentpayments.SilentPayments.RecipientKeys
import com.gorunjinian.vaultovich.silentpayments.SilentPayments.SilentPaymentMathException
import com.gorunjinian.vaultovich.silentpayments.SilentPayments.SpentInput
import com.gorunjinian.vaultovich.utils.Either
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * BIP-352 sender-side key checks, BIP-375 signer rules, and spending a received silent payment.
 */
class SilentPaymentSignerTest {

    private val master = DeterministicWallet.generate(ByteVector(ByteArray(32) { 21 }))
    private fun key(i: Int): PrivateKey = master.derivePrivateKey(KeyPath("m/86'/1'/0'/0/$i")).privateKey
    private fun op(i: Int) = OutPoint(TxHash(ByteVector32(ByteArray(32) { i.toByte() })), 0)
    private fun spk(elts: List<ScriptElt>) = ByteVector(Script.write(elts))
    private val recipient = SilentPaymentAddress.decode(
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
    )

    private fun assertKeyMismatch(block: () -> Any?) {
        val e = runCatching(block).exceptionOrNull()
        assertTrue("expected KEY_DOES_NOT_MATCH_INPUT, got $e", e is SilentPaymentMathException && e.reason == FailureReason.KEY_DOES_NOT_MATCH_INPUT)
    }

    // ------------------------------------------------------------------ BIP-352 input keys

    @Test
    fun taprootInputsRequireTheOutputKeyPrivateKey() {
        // BIP-352: "the sender uses the private key corresponding to the taproot output key (i.e. the
        // tweaked private key)". Handing over the BIP-86 internal key would derive a payment nobody
        // can find.
        val internal = key(1)
        val bip86 = spk(Script.pay2tr(internal.xOnlyPublicKey(), null as ScriptTree?))
        assertKeyMismatch { SilentPayments.eligibleKey(SpentInput(op(1), internal, bip86)) }

        val outputPriv = SilentPayments.taprootOutputPrivateKey(internal)
        val eligible = SilentPayments.eligibleKey(SpentInput(op(1), outputPriv, bip86))!!
        assertTrue(eligible.isTaproot)
        assertEquals(Script.pay2trOutputKey(bip86), eligible.privateKey.xOnlyPublicKey())

        // With a script tree the tweak commits to its root.
        val root = ByteVector32(Crypto.sha256("leaf".encodeToByteArray()))
        val withTree = spk(Script.pay2tr(internal.xOnlyPublicKey(), root))
        assertKeyMismatch { SilentPayments.eligibleKey(SpentInput(op(1), outputPriv, withTree)) }
        assertEquals(Script.pay2trOutputKey(withTree), SilentPayments.eligibleKey(SpentInput(op(1), SilentPayments.taprootOutputPrivateKey(internal, root), withTree))!!.privateKey.xOnlyPublicKey())
    }

    @Test
    fun keyHashInputsMustMatchTheKey() {
        val k = key(2)
        val p2wpkh = spk(Script.pay2wpkh(k.publicKey()))
        assertEquals(false, SilentPayments.eligibleKey(SpentInput(op(2), k, p2wpkh))!!.isTaproot)
        assertKeyMismatch { SilentPayments.eligibleKey(SpentInput(op(2), key(3), p2wpkh)) }

        val p2pkh = spk(Script.pay2pkh(k.publicKey()))
        assertEquals(k, SilentPayments.eligibleKey(SpentInput(op(3), k, p2pkh))!!.privateKey)
        assertKeyMismatch { SilentPayments.eligibleKey(SpentInput(op(3), key(3), p2pkh)) }

        val redeem = Script.pay2wpkh(k.publicKey())
        val nested = spk(Script.pay2sh(redeem))
        assertEquals(k, SilentPayments.eligibleKey(SpentInput(op(4), k, nested, ByteVector(Script.write(redeem))))!!.privateKey)
        assertKeyMismatch { SilentPayments.eligibleKey(SpentInput(op(4), key(3), nested, ByteVector(Script.write(redeem)))) }
        // A redeem script that does not hash to the scriptPubKey is a lie about the input.
        assertKeyMismatch { SilentPayments.eligibleKey(SpentInput(op(4), k, nested, ByteVector(Script.write(Script.pay2wpkh(key(3).publicKey()))))) }
    }

    @Test
    fun uncompressedKeyInputsAreSkippedNotUsed() {
        // BIP-352: "only X-only and compressed public keys are permitted"; receivers skip inputs whose
        // scriptSig / witness key is uncompressed, so the sender must leave them out of the sum.
        val k = key(2)
        val uncompressedHash = Crypto.hash160(k.publicKey().toUncompressedBin())
        assertNull(SilentPayments.eligibleKey(SpentInput(op(5), k, spk(Script.pay2pkh(uncompressedHash)))))
        assertNull(SilentPayments.eligibleKey(SpentInput(op(5), k, spk(Script.pay2wpkh(uncompressedHash)))))
    }

    @Test
    fun otherScriptTypesAreIneligible() {
        val k = key(2)
        val p2wsh = spk(Script.pay2wsh(Script.pay2wpkh(k.publicKey())))
        assertNull(SilentPayments.eligibleKey(SpentInput(op(6), k, p2wsh)))
        // P2SH without a redeem script cannot be classified as P2SH-P2WPKH.
        assertNull(SilentPayments.eligibleKey(SpentInput(op(6), k, spk(Script.pay2sh(Script.pay2wpkh(k.publicKey()))))))
    }

    @Test
    fun deriveOutputsFromInputsUsesEveryOutpointForTheInputHash() {
        val a = key(7); val b = key(8); val c = key(9)
        val inputs = listOf(
            SpentInput(OutPoint(TxHash(ByteVector32(ByteArray(32) { 0x7f })), 3), a, spk(Script.pay2wpkh(a.publicKey()))),
            SpentInput(OutPoint(TxHash(ByteVector32(ByteArray(32) { 0x7e })), 0), b, spk(Script.pay2wpkh(b.publicKey()))),
            // Ineligible (P2WSH) but its outpoint is the smallest, and BIP-352 takes the smallest over *all* inputs.
            SpentInput(OutPoint(TxHash(ByteVector32(ByteArray(32))), 0), c, spk(Script.pay2wsh(Script.pay2wpkh(c.publicKey())))),
        )
        val recipients = listOf(RecipientKeys(recipient.scanPubKey, recipient.spendPubKey))
        val derived = SilentPayments.deriveOutputs(inputs, recipients)
        val eligible = SilentPayments.eligibleKeys(inputs)
        assertEquals(2, eligible.size)
        assertEquals(SilentPayments.deriveOutputs(eligible, inputs.map { it.outPoint }, recipients), derived)
        assertNotEquals(SilentPayments.deriveOutputs(eligible, inputs.take(2).map { it.outPoint }, recipients), derived)
    }

    @Test
    fun sameScanKeyRecipientsGetKInAscendingSpendKeyOrder() {
        // BIP-375: "If there are multiple silent payment codes with the same scan key, sort the codes
        // lexicographically in ascending order to determine the ordering of the k value."
        val spendA = key(10).publicKey(); val spendB = key(11).publicKey()
        val (lo, hi) = if (spendA.value.toHex() < spendB.value.toHex()) spendA to spendB else spendB to spendA
        val a = key(7)
        val inputs = listOf(SpentInput(op(1), a, spk(Script.pay2wpkh(a.publicKey()))))
        // Hand the larger spend key first: it must still get k = 1.
        val recipients = listOf(RecipientKeys(recipient.scanPubKey, hi), RecipientKeys(recipient.scanPubKey, lo))
        val derived = SilentPayments.deriveOutputs(inputs, recipients).associate { it.recipientIndex to it.outputKey }

        val sum = SilentPayments.summedPrivateKey(SilentPayments.eligibleKeys(inputs))
        val hash = SilentPayments.inputHash(SilentPayments.smallestOutpoint(inputs.map { it.outPoint }), sum.publicKey())
        val secret = SilentPayments.sharedSecret(hash, sum, recipient.scanPubKey)
        assertEquals(SilentPayments.outputKey(lo, secret, 0), derived[1])
        assertEquals(SilentPayments.outputKey(hi, secret, 1), derived[0])
    }

    // ------------------------------------------------------------------ BIP-375 signer rules

    private fun prevTx(script: List<ScriptElt>, salt: Int) = Transaction(
        2, listOf(TxIn(OutPoint(TxHash(ByteVector32(ByteArray(32) { salt.toByte() })), 0), ByteVector.empty, 0)),
        listOf(TxOut(Satoshi(100_000), ByteVector(Script.write(script)))), 0,
    )

    private fun witnessInput(prev: Transaction, sighash: Int? = null, unknown: List<DataEntry> = emptyList(), withPrev: Boolean = true) =
        Input.WitnessInput.PartiallySignedWitnessInput(
            prev.txOut[0], if (withPrev) prev else null, sighash, emptyMap(), emptyMap(), null, null,
            emptySet(), emptySet(), emptySet(), emptySet(), null, emptyMap(), null, unknown,
        )

    private val spInfoEntry = DataEntry(ByteVector("09"), ByteVector(recipient.scanPubKey.value.toByteArray() + recipient.spendPubKey.value.toByteArray()))

    /** A v2 PSBT paying one silent-payment output (script already derived unless [outputScript] is empty). */
    private fun spPsbt(
        version: Long = 2,
        outputScript: ByteVector = spk(Script.pay2tr(key(30).xOnlyPublicKey())),
        inputs: List<Pair<Transaction, Input>>,
    ): Psbt {
        val tx = Transaction(
            2,
            inputs.map { (prev, _) -> TxIn(OutPoint(prev, 0), ByteVector.empty, TxIn.SEQUENCE_FINAL) },
            listOf(TxOut(Satoshi(90_000), outputScript)),
            0,
        )
        return Psbt(Global(version, tx, emptyList(), emptyList()), inputs.map { it.second }, listOf(Output.UnspecifiedOutput(emptyMap(), null, emptyMap(), listOf(spInfoEntry))))
    }

    private fun assertViolation(result: Either<UpdateFailure, *>, fragment: String) {
        val f = (result as? Either.Left)?.value
        assertTrue("expected SilentPaymentRuleViolation containing '$fragment', got $result", f is UpdateFailure.SilentPaymentRuleViolation && f.reason.contains(fragment))
    }

    @Test
    fun silentPaymentPsbtSignsUnderDefaults() {
        val k = key(12)
        val prev = prevTx(Script.pay2wpkh(k.publicKey()), 1)
        val psbt = spPsbt(inputs = listOf(prev to witnessInput(prev)))
        assertTrue(psbt.sign(k, 0) is Either.Right)
        assertTrue(psbt.sign(k, 0, SignPolicy.Permissive) is Either.Right)
        val explicitAll = spPsbt(inputs = listOf(prev to witnessInput(prev, SigHash.SIGHASH_ALL)))
        assertTrue(explicitAll.sign(k, 0) is Either.Right)
    }

    @Test
    fun sighashOtherThanAllIsRefusedEvenWhenThePolicyAllowsIt() {
        val k = key(12)
        val prev = prevTx(Script.pay2wpkh(k.publicKey()), 1)
        for (type in listOf(SigHash.SIGHASH_NONE, SigHash.SIGHASH_SINGLE, 0x81)) {
            val psbt = spPsbt(inputs = listOf(prev to witnessInput(prev, type)))
            assertViolation(psbt.sign(k, 0, SignPolicy.Permissive), "SIGHASH_ALL")
        }
    }

    @Test
    fun taprootInputsAcceptDefaultAndAllOnly() {
        val internal = key(13)
        val prev = prevTx(Script.pay2tr(internal.xOnlyPublicKey(), null as ScriptTree?), 2)
        assertTrue(spPsbt(inputs = listOf(prev to witnessInput(prev, null, withPrev = false))).sign(internal, 0) is Either.Right)
        assertTrue(spPsbt(inputs = listOf(prev to witnessInput(prev, SigHash.SIGHASH_ALL, withPrev = false))).sign(internal, 0) is Either.Right)
        assertViolation(spPsbt(inputs = listOf(prev to witnessInput(prev, 0x81, withPrev = false))).sign(internal, 0, SignPolicy.Permissive), "SIGHASH_ALL")
    }

    @Test
    fun outputScriptMustBeDerivedBeforeSigning() {
        val k = key(12)
        val prev = prevTx(Script.pay2wpkh(k.publicKey()), 1)
        val psbt = spPsbt(outputScript = ByteVector.empty, inputs = listOf(prev to witnessInput(prev)))
        assertViolation(psbt.sign(k, 0), "no script yet")
    }

    @Test
    fun silentPaymentPsbtMustBeVersion2() {
        val k = key(12)
        val prev = prevTx(Script.pay2wpkh(k.publicKey()), 1)
        val psbt = spPsbt(version = 0, inputs = listOf(prev to witnessInput(prev)))
        assertViolation(psbt.sign(k, 0), "version 2")
    }

    @Test
    fun inputsSpendingSegwitAboveVersion1AreRefused() {
        val k = key(12)
        val prev = prevTx(Script.pay2wpkh(k.publicKey()), 1)
        val future = prevTx(listOf(OP_2, OP_PUSHDATA(ByteArray(32) { 9 })), 3)
        val psbt = spPsbt(inputs = listOf(prev to witnessInput(prev), future to witnessInput(future)))
        assertViolation(psbt.sign(k, 0), "segwit version 2")
    }

    // ------------------------------------------------------------------ spending a received payment

    @Test
    fun spendsAReceivedSilentPaymentWithTheTweak() {
        val bSpend = key(14)
        val tweak = ByteVector32(Crypto.sha256("t_k".encodeToByteArray()))
        val d = SilentPaymentSpending.deriveSpendingPrivateKey(bSpend, tweak)
        val outputKey = d.xOnlyPublicKey()
        val prev = prevTx(Script.pay2tr(outputKey), 4) // raw output key: silent-payment outputs carry no TapTweak
        val tweakEntry = DataEntry(ByteVector("20"), ByteVector(tweak.toByteArray()))
        val tx = Transaction(2, listOf(TxIn(OutPoint(prev, 0), ByteVector.empty, TxIn.SEQUENCE_FINAL)), listOf(TxOut(Satoshi(90_000), spk(Script.pay2wpkh(key(1).publicKey())))), 0)
        val psbt = Psbt(Global(2, tx, emptyList(), emptyList()), listOf(witnessInput(prev, null, listOf(tweakEntry), withPrev = false)), listOf(Output.UnspecifiedOutput(emptyMap(), null, emptyMap(), emptyList())))

        val signed = (psbt.sign(bSpend, 0) as Either.Right).value
        assertEquals(64, signed.sig.size())
        val digest = tx.hashForSigningTaprootKeyPath(0, listOf(prev.txOut[0]), SigHash.SIGHASH_DEFAULT)
        assertTrue(Crypto.verifySignatureSchnorr(digest, signed.sig, outputKey))

        // Without the tweak the key path check fails (the output key is not BIP-86 of b_spend).
        val noTweak = psbt.copy(inputs = listOf(witnessInput(prev, null, emptyList(), withPrev = false)))
        assertTrue(noTweak.sign(bSpend, 0) is Either.Left)
        // A wrong tweak is refused rather than producing an invalid signature.
        val wrong = DataEntry(ByteVector("20"), ByteVector(ByteArray(32) { 3 }))
        val badTweak = psbt.copy(inputs = listOf(witnessInput(prev, null, listOf(wrong), withPrev = false)))
        val result = badTweak.sign(bSpend, 0)
        assertTrue("expected CannotSignInput, got $result", (result as? Either.Left)?.value is UpdateFailure.CannotSignInput)
    }

    // ------------------------------------------------------------------ per-input BIP-375 fields

    @Test
    fun perInputShareAndProofEntriesRoundTrip() {
        val k = key(15)
        val prev = prevTx(Script.pay2wpkh(k.publicKey()), 5)
        val share = SilentPayments.ecdhShare(k, recipient.scanPubKey)
        val proof = DleqProof.generate(k, recipient.scanPubKey, ByteArray(32) { 8 })!!
        val entries = listOf(
            Bip374Fields.inputEcdhShareEntry(recipient.scanPubKey, share),
            Bip374Fields.inputDleqProofEntry(recipient.scanPubKey, proof),
        )
        val psbt = spPsbt(inputs = listOf(prev to witnessInput(prev, null, entries)))
        assertTrue(psbt.hasSilentPaymentFields)
        val reread = (Psbt.read(Psbt.write(psbt)) as Either.Right).value
        assertEquals(mapOf(recipient.scanPubKey to share), reread.inputs[0].silentPaymentEcdhShares)
        assertEquals(mapOf(recipient.scanPubKey to ByteVector(proof)), reread.inputs[0].silentPaymentDleqProofs)
        // The proof verifies against the input's public key: A = a·G, C = a·B_scan.
        assertTrue(DleqProof.verify(k.publicKey(), recipient.scanPubKey, share, proof))
    }
}
