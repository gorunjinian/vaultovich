package com.gorunjinian.vaultovich

import com.gorunjinian.vaultovich.utils.Either
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The signer refuses keys the input's script does not reference, and unknown witness programs. */
class SignerKeyMatchTest {

    private val master = DeterministicWallet.generate(ByteVector(ByteArray(32) { 11 }))
    private fun key(i: Int): PrivateKey = master.derivePrivateKey(KeyPath("m/84'/1'/0'/0/$i")).privateKey
    private val k0 = key(0)
    private val k1 = key(1)
    private val k2 = key(2)
    private val stranger = key(99)

    private fun prevTx(script: List<ScriptElt>, salt: Int) = Transaction(
        2,
        listOf(TxIn(OutPoint(TxHash(ByteVector32(ByteArray(32) { salt.toByte() })), 0), ByteVector.empty, 0)),
        listOf(TxOut(Satoshi(100_000), ByteVector(Script.write(script)))),
        0,
    )

    private fun spend(prev: Transaction) = Transaction(
        2,
        listOf(TxIn(OutPoint(prev, 0), ByteVector.empty, TxIn.SEQUENCE_FINAL)),
        listOf(TxOut(Satoshi(90_000), ByteVector(Script.write(Script.pay2wpkh(k0.publicKey()))))),
        0,
    )

    private fun witnessPsbt(prev: Transaction, redeemScript: List<ScriptElt>? = null, witnessScript: List<ScriptElt>? = null): Psbt {
        val input = Input.WitnessInput.PartiallySignedWitnessInput(
            prev.txOut[0], prev, null, emptyMap(), emptyMap(), redeemScript, witnessScript,
            emptySet(), emptySet(), emptySet(), emptySet(), null, emptyMap(), null, emptyList(),
        )
        return Psbt(Global(0, spend(prev), emptyList(), emptyList()), listOf(input), listOf(Output.UnspecifiedOutput(emptyMap(), null, emptyMap(), emptyList())))
    }

    private fun legacyPsbt(prev: Transaction, redeemScript: List<ScriptElt>? = null): Psbt {
        val input = Input.NonWitnessInput.PartiallySignedNonWitnessInput(
            prev, 0, null, emptyMap(), emptyMap(), redeemScript, emptySet(), emptySet(), emptySet(), emptySet(), emptyList(),
        )
        return Psbt(Global(0, spend(prev), emptyList(), emptyList()), listOf(input), listOf(Output.UnspecifiedOutput(emptyMap(), null, emptyMap(), emptyList())))
    }

    private fun assertKeyRefused(result: Either<UpdateFailure, SignPsbtResult>) =
        assertEquals(UpdateFailure.KeyDoesNotMatchInput(0), (result as? Either.Left)?.value)

    private fun assertSigned(result: Either<UpdateFailure, SignPsbtResult>) =
        assertTrue("expected Right, got $result", result is Either.Right)

    @Test
    fun p2wpkhRefusesAnUnrelatedKey() {
        val psbt = witnessPsbt(prevTx(Script.pay2wpkh(k0.publicKey()), 1))
        assertKeyRefused(psbt.sign(stranger, 0))
        assertSigned(psbt.sign(k0, 0))
    }

    @Test
    fun p2shP2wpkhRefusesAnUnrelatedKey() {
        val redeem = Script.pay2wpkh(k0.publicKey())
        val psbt = witnessPsbt(prevTx(Script.pay2sh(redeem), 2), redeemScript = redeem)
        assertKeyRefused(psbt.sign(stranger, 0))
        assertSigned(psbt.sign(k0, 0))
    }

    @Test
    fun p2wshMultisigSignsMembersOnly() {
        val witness = Script.createMultiSigMofN(2, listOf(k0.publicKey(), k1.publicKey(), k2.publicKey()))
        val psbt = witnessPsbt(prevTx(Script.pay2wsh(witness), 3), witnessScript = witness)
        assertKeyRefused(psbt.sign(stranger, 0))
        assertSigned(psbt.sign(k0, 0))
        assertSigned(psbt.sign(k2, 0))

        val nested = witnessPsbt(prevTx(Script.pay2sh(Script.pay2wsh(witness)), 4), redeemScript = Script.pay2wsh(witness), witnessScript = witness)
        assertKeyRefused(nested.sign(stranger, 0))
        assertSigned(nested.sign(k1, 0))
    }

    @Test
    fun legacyP2pkhAndP2shRefuseUnrelatedKeys() {
        val p2pkh = legacyPsbt(prevTx(Script.pay2pkh(k0.publicKey()), 5))
        assertKeyRefused(p2pkh.sign(stranger, 0))
        assertSigned(p2pkh.sign(k0, 0))

        val redeem = Script.createMultiSigMofN(1, listOf(k1.publicKey(), k2.publicKey()))
        val p2sh = legacyPsbt(prevTx(Script.pay2sh(redeem), 6), redeemScript = redeem)
        assertKeyRefused(p2sh.sign(k0, 0))
        assertSigned(p2sh.sign(k2, 0))
    }

    @Test
    fun unknownWitnessProgramsAreRefused() {
        // Witness v2 with a 32-byte program: no signing semantics exist; previously signed anyway.
        val v2 = listOf(OP_2, OP_PUSHDATA(ByteArray(32) { 7 }))
        val psbt = witnessPsbt(prevTx(v2, 7), witnessScript = Script.pay2pkh(k0.publicKey()))
        val result = psbt.sign(k0, 0, SignPolicy.Permissive)
        assertTrue("expected CannotSignInput, got $result", (result as? Either.Left)?.value is UpdateFailure.CannotSignInput)
        // Witness v1 with a 20-byte program is likewise undefined.
        val v1Short = listOf(OP_1, OP_PUSHDATA(ByteArray(20) { 7 }))
        assertTrue(witnessPsbt(prevTx(v1Short, 8)).sign(k0, 0, SignPolicy.Permissive) is Either.Left)
    }
}
