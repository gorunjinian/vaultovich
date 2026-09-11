package com.gorunjinian.vaultovich

import com.gorunjinian.vaultovich.utils.Either
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The signer's [SignPolicy]: what a hardware signer must refuse by default.
 *
 *  - BIP-174 signer role / CVE-2020-14199: a segwit v0 input is only signed when the previous
 *    transaction (`PSBT_IN_NON_WITNESS_UTXO`) is present and consistent with `PSBT_IN_WITNESS_UTXO`.
 *  - Only SIGHASH_ALL / SIGHASH_DEFAULT unless the host opts in.
 *  - SIGHASH_SINGLE with no matching output is never signed: for legacy inputs the digest degenerates
 *    to the constant `1` (Bitcoin Core `SignatureHash`), a signature over nothing.
 */
class SignPolicyTest {

    private val seed = ByteVector(ByteArray(32) { 5 })
    private val master = DeterministicWallet.generate(seed)
    private fun key(i: Int): PrivateKey = master.derivePrivateKey(KeyPath("m/84'/1'/0'/0/$i")).privateKey

    private val k0 = key(0)
    private val k1 = key(1)
    private val p2wpkh0 = Script.write(Script.pay2wpkh(k0.publicKey())).byteVector()
    private val p2wpkh1 = Script.write(Script.pay2wpkh(k1.publicKey())).byteVector()
    private val p2pkh0 = Script.write(Script.pay2pkh(k0.publicKey())).byteVector()
    private val p2tr0 = Script.write(Script.pay2tr(k0.publicKey().xOnly(), null as ScriptTree?)).byteVector()

    /** A confirmed-looking previous transaction paying [amount] to [script] at output 0. */
    private fun prevTx(amount: Long, script: ByteVector, salt: Int): Transaction = Transaction(
        version = 2,
        txIn = listOf(TxIn(OutPoint(TxHash(ByteVector32(ByteArray(32) { salt.toByte() })), 0), ByteVector.empty, 0)),
        txOut = listOf(TxOut(Satoshi(amount), script)),
        lockTime = 0,
    )

    private fun witnessInput(witnessUtxo: TxOut, nonWitnessUtxo: Transaction? = null, sighash: Int? = null) =
        Input.WitnessInput.PartiallySignedWitnessInput(
            witnessUtxo, nonWitnessUtxo, sighash, emptyMap(), emptyMap(), null, null,
            emptySet(), emptySet(), emptySet(), emptySet(), null, emptyMap(), null, emptyList(),
        )

    private fun legacyInput(prev: Transaction, sighash: Int? = null) =
        Input.NonWitnessInput.PartiallySignedNonWitnessInput(
            prev, 0, sighash, emptyMap(), emptyMap(), null, emptySet(), emptySet(), emptySet(), emptySet(), emptyList(),
        )

    private fun unspecifiedOutput() = Output.UnspecifiedOutput(emptyMap(), null, emptyMap(), emptyList())

    private fun psbt(prevs: List<Transaction>, inputs: List<Input>, outputs: List<TxOut>): Psbt {
        val tx = Transaction(
            version = 2,
            txIn = prevs.map { TxIn(OutPoint(it, 0), ByteVector.empty, TxIn.SEQUENCE_FINAL) },
            txOut = outputs,
            lockTime = 0,
        )
        return Psbt(Global(0, tx, emptyList(), emptyList()), inputs, outputs.map { unspecifiedOutput() })
    }

    private inline fun <reified T : UpdateFailure> assertRefused(result: Either<UpdateFailure, SignPsbtResult>) {
        assertTrue("expected Left, got $result", result is Either.Left)
        val failure = (result as Either.Left).value
        assertTrue("expected ${T::class.simpleName}, got $failure", failure is T)
    }

    private fun assertSigned(result: Either<UpdateFailure, SignPsbtResult>): SignPsbtResult {
        assertTrue("expected Right, got $result", result is Either.Right)
        return (result as Either.Right).value
    }

    // ---------------------------------------------------------------- non_witness_utxo requirement

    @Test
    fun segwitV0WithWitnessUtxoOnlyIsRefusedByDefault() {
        val prev = prevTx(100_000, p2wpkh0, 1)
        val psbt = psbt(listOf(prev), listOf(witnessInput(prev.txOut[0])), listOf(TxOut(Satoshi(90_000), p2wpkh1)))
        assertRefused<UpdateFailure.MissingNonWitnessUtxo>(psbt.sign(k0, 0))
        assertEquals(UpdateFailure.MissingNonWitnessUtxo(0), (psbt.sign(k0, 0) as Either.Left).value)
    }

    @Test
    fun segwitV0WithWitnessUtxoOnlySignsWhenTrusted() {
        val prev = prevTx(100_000, p2wpkh0, 1)
        val psbt = psbt(listOf(prev), listOf(witnessInput(prev.txOut[0])), listOf(TxOut(Satoshi(90_000), p2wpkh1)))
        assertSigned(psbt.sign(k0, 0, SignPolicy(trustWitnessUtxo = true)))
    }

    @Test
    fun segwitV0WithMatchingNonWitnessUtxoSignsAndExtracts() {
        val prev = prevTx(100_000, p2wpkh0, 1)
        val psbt = psbt(listOf(prev), listOf(witnessInput(prev.txOut[0], prev)), listOf(TxOut(Satoshi(90_000), p2wpkh1)))
        val signed = assertSigned(psbt.sign(k0, 0))
        val finalized = (signed.psbt.finalizeWitnessInput(0, ScriptWitness(listOf(signed.sig, k0.publicKey().value))) as Either.Right).value
        val tx = (finalized.extract() as Either.Right).value
        Transaction.correctlySpends(tx, mapOf(tx.txIn[0].outPoint to prev.txOut[0]), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun nonWitnessUtxoDisagreeingWithWitnessUtxoIsRefused() {
        val prev = prevTx(100_000, p2wpkh0, 1)
        // The creator claims 1 BTC in witness_utxo while the real previous output pays 100k sat.
        val lie = TxOut(Satoshi(100_000_000), p2wpkh0)
        val psbt = psbt(listOf(prev), listOf(witnessInput(lie, prev)), listOf(TxOut(Satoshi(90_000), p2wpkh1)))
        assertRefused<UpdateFailure.InvalidNonWitnessUtxo>(psbt.sign(k0, 0))
        // Even a host that trusts witness_utxo must not accept a contradicting previous transaction.
        assertRefused<UpdateFailure.InvalidNonWitnessUtxo>(psbt.sign(k0, 0, SignPolicy.Permissive))
    }

    @Test
    fun nonWitnessUtxoWithWrongTxidIsRefused() {
        val prev = prevTx(100_000, p2wpkh0, 1)
        val other = prevTx(100_000, p2wpkh0, 2)
        val psbt = psbt(listOf(prev), listOf(witnessInput(prev.txOut[0], other)), listOf(TxOut(Satoshi(90_000), p2wpkh1)))
        assertRefused<UpdateFailure.InvalidNonWitnessUtxo>(psbt.sign(k0, 0))
    }

    @Test
    fun taprootWithWitnessUtxoOnlySignsByDefault() {
        // BIP-341 commits to every input amount under SIGHASH_DEFAULT, so the previous tx is not needed.
        val prev = prevTx(100_000, p2tr0, 1)
        val psbt = psbt(listOf(prev), listOf(witnessInput(prev.txOut[0])), listOf(TxOut(Satoshi(90_000), p2wpkh1)))
        val signed = assertSigned(psbt.sign(k0, 0))
        assertEquals(64, signed.sig.size())
    }

    @Test
    fun mixedTransactionStillRequiresPreviousTxForTheSegwitV0Input() {
        val prevTr = prevTx(100_000, p2tr0, 1)
        val prevV0 = prevTx(100_000, p2wpkh1, 2)
        val psbt = psbt(
            listOf(prevTr, prevV0),
            listOf(witnessInput(prevTr.txOut[0]), witnessInput(prevV0.txOut[0])),
            listOf(TxOut(Satoshi(190_000), p2wpkh1)),
        )
        assertSigned(psbt.sign(k0, 0))
        assertRefused<UpdateFailure.MissingNonWitnessUtxo>(psbt.sign(k1, 1))
    }

    // ------------------------------------------------------------------------ sighash allow-list

    @Test
    fun sighashNoneIsRefusedByDefaultOnSegwitV0() {
        val prev = prevTx(100_000, p2wpkh0, 1)
        val psbt = psbt(listOf(prev), listOf(witnessInput(prev.txOut[0], prev, SigHash.SIGHASH_NONE)), listOf(TxOut(Satoshi(90_000), p2wpkh1)))
        assertEquals(UpdateFailure.SighashTypeNotAllowed(0, SigHash.SIGHASH_NONE), (psbt.sign(k0, 0) as Either.Left).value)
        assertSigned(psbt.sign(k0, 0, SignPolicy.Permissive))
    }

    @Test
    fun sighashAllAnyoneCanPayIsRefusedByDefaultOnLegacy() {
        val prev = prevTx(100_000, p2pkh0, 1)
        val psbt = psbt(listOf(prev), listOf(legacyInput(prev, 0x81)), listOf(TxOut(Satoshi(90_000), p2wpkh1)))
        assertRefused<UpdateFailure.SighashTypeNotAllowed>(psbt.sign(k0, 0))
        assertSigned(psbt.sign(k0, 0, SignPolicy(allowedSighashTypes = setOf(0x81))))
    }

    @Test
    fun taprootAnyoneCanPayIsRefusedByDefault() {
        val prev = prevTx(100_000, p2tr0, 1)
        val psbt = psbt(listOf(prev), listOf(witnessInput(prev.txOut[0], null, 0x81)), listOf(TxOut(Satoshi(90_000), p2wpkh1)))
        assertRefused<UpdateFailure.SighashTypeNotAllowed>(psbt.sign(k0, 0))
        val signed = assertSigned(psbt.sign(k0, 0, SignPolicy.Permissive))
        assertEquals(65, signed.sig.size())
        assertEquals(0x81.toByte(), signed.sig[64])
    }

    @Test
    fun explicitSighashAllIsAcceptedEverywhere() {
        val prevV0 = prevTx(100_000, p2wpkh0, 1)
        val prevLegacy = prevTx(100_000, p2pkh0, 2)
        val prevTr = prevTx(100_000, p2tr0, 3)
        val psbt = psbt(
            listOf(prevV0, prevLegacy, prevTr),
            listOf(
                witnessInput(prevV0.txOut[0], prevV0, SigHash.SIGHASH_ALL),
                legacyInput(prevLegacy, SigHash.SIGHASH_ALL),
                witnessInput(prevTr.txOut[0], null, SigHash.SIGHASH_ALL),
            ),
            listOf(TxOut(Satoshi(290_000), p2wpkh1)),
        )
        assertSigned(psbt.sign(k0, 0))
        assertSigned(psbt.sign(k0, 1))
        // Taproot with an explicit SIGHASH_ALL (0x01) appends the byte; SIGHASH_DEFAULT would not.
        assertEquals(65, assertSigned(psbt.sign(k0, 2)).sig.size())
    }

    @Test
    fun undefinedSighashIsStillReportedAsUnsupportedNotDisallowed() {
        val prev = prevTx(100_000, p2wpkh0, 1)
        val psbt = psbt(listOf(prev), listOf(witnessInput(prev.txOut[0], prev, 0x41)), listOf(TxOut(Satoshi(90_000), p2wpkh1)))
        assertRefused<UpdateFailure.UnsupportedSighashType>(psbt.sign(k0, 0, SignPolicy.Permissive))
    }

    // --------------------------------------------------------- SIGHASH_SINGLE without an output

    @Test
    fun legacySighashSingleWithoutMatchingOutputIsNeverSigned() {
        val prev0 = prevTx(50_000, p2pkh0, 1)
        val prev1 = prevTx(50_000, p2pkh0, 2)
        val psbt = psbt(
            listOf(prev0, prev1),
            listOf(legacyInput(prev0, SigHash.SIGHASH_SINGLE), legacyInput(prev1, SigHash.SIGHASH_SINGLE)),
            listOf(TxOut(Satoshi(90_000), p2wpkh1)),
        )
        // Input 0 has a matching output; only refused by the default allow-list.
        assertRefused<UpdateFailure.SighashTypeNotAllowed>(psbt.sign(k0, 0))
        assertSigned(psbt.sign(k0, 0, SignPolicy.Permissive))
        // Input 1 has none: the digest would be the constant 1. Refused regardless of policy.
        assertEquals(UpdateFailure.SighashSingleWithoutMatchingOutput(1), (psbt.sign(k0, 1, SignPolicy.Permissive) as Either.Left).value)
    }

    @Test
    fun segwitV0SighashSingleWithoutMatchingOutputIsRefused() {
        val prev0 = prevTx(50_000, p2wpkh0, 1)
        val prev1 = prevTx(50_000, p2wpkh0, 2)
        val psbt = psbt(
            listOf(prev0, prev1),
            listOf(witnessInput(prev0.txOut[0], prev0, 0x83), witnessInput(prev1.txOut[0], prev1, 0x83)),
            listOf(TxOut(Satoshi(90_000), p2wpkh1)),
        )
        assertSigned(psbt.sign(k0, 0, SignPolicy.Permissive))
        assertRefused<UpdateFailure.SighashSingleWithoutMatchingOutput>(psbt.sign(k0, 1, SignPolicy.Permissive))
    }

    @Test
    fun taprootSighashSingleWithoutMatchingOutputIsRefusedNotThrown() {
        val prev0 = prevTx(50_000, p2tr0, 1)
        val prev1 = prevTx(50_000, p2tr0, 2)
        val psbt = psbt(
            listOf(prev0, prev1),
            listOf(witnessInput(prev0.txOut[0], null, SigHash.SIGHASH_SINGLE), witnessInput(prev1.txOut[0], null, SigHash.SIGHASH_SINGLE)),
            listOf(TxOut(Satoshi(90_000), p2wpkh1)),
        )
        assertSigned(psbt.sign(k0, 0, SignPolicy.Permissive))
        assertRefused<UpdateFailure.SighashSingleWithoutMatchingOutput>(psbt.sign(k0, 1, SignPolicy.Permissive))
    }

    @Test
    fun outPointOverloadHonoursPolicy() {
        val prev = prevTx(100_000, p2wpkh0, 1)
        val psbt = psbt(listOf(prev), listOf(witnessInput(prev.txOut[0])), listOf(TxOut(Satoshi(90_000), p2wpkh1)))
        val outPoint = psbt.global.tx.txIn[0].outPoint
        assertRefused<UpdateFailure.MissingNonWitnessUtxo>(psbt.sign(k0, outPoint))
        assertSigned(psbt.sign(k0, outPoint, SignPolicy.Permissive))
    }
}
