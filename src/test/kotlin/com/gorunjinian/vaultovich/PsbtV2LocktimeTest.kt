package com.gorunjinian.vaultovich

import com.gorunjinian.vaultovich.crypto.Pack
import com.gorunjinian.vaultovich.utils.Either
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** BIP-370 "Determining Lock Time", exercised through a v2 write / read round trip. */
class PsbtV2LocktimeTest {

    private val key = DeterministicWallet.generate(ByteVector(ByteArray(32) { 31 })).derivePrivateKey(KeyPath("m/84'/1'/0'/0/0")).privateKey
    private val script = ByteVector(Script.write(Script.pay2wpkh(key.publicKey())))

    private fun entry(type: Int, value: Long) = DataEntry(ByteVector(byteArrayOf(type.toByte())), ByteVector(Pack.writeInt32LE(value.toInt())))
    private fun height(v: Long) = entry(0x12, v)
    private fun time(v: Long) = entry(0x11, v)

    /** One v2 input per entry list; each list is that input's required-locktime fields. */
    private fun psbt(fallback: Long?, vararg inputFields: List<DataEntry>): ByteVector {
        val tx = Transaction(
            2,
            inputFields.indices.map { i -> TxIn(OutPoint(TxHash(ByteVector32(ByteArray(32) { (i + 1).toByte() })), 0), ByteVector.empty, TxIn.SEQUENCE_FINAL) },
            listOf(TxOut(Satoshi(50_000), script)),
            0,
        )
        val inputs = inputFields.map { fields ->
            Input.WitnessInput.PartiallySignedWitnessInput(
                TxOut(Satoshi(100_000), script), null, null, emptyMap(), emptyMap(), null, null,
                emptySet(), emptySet(), emptySet(), emptySet(), null, emptyMap(), null, fields,
            )
        }
        val global = Global(2, tx, emptyList(), emptyList(), fallbackLocktime = fallback)
        return Psbt.write(Psbt(global, inputs, listOf(Output.UnspecifiedOutput(emptyMap(), null, emptyMap(), emptyList()))))
    }

    private fun locktimeOf(bytes: ByteVector): Long {
        val result = Psbt.read(bytes)
        assertTrue("expected Right, got $result", result is Either.Right)
        return (result as Either.Right).value.global.tx.lockTime
    }

    private fun assertRejected(bytes: ByteVector) {
        val result = Psbt.read(bytes)
        assertTrue("expected InvalidTxInput, got $result", (result as? Either.Left)?.value is ParseFailure.InvalidTxInput)
    }

    @Test
    fun fallbackIsUsedWhenNoInputConstrainsTheLocktime() {
        assertEquals(0L, locktimeOf(psbt(null, emptyList())))
        assertEquals(700_000L, locktimeOf(psbt(700_000, emptyList(), emptyList())))
    }

    @Test
    fun unconstrainedInputsDoNotVetoTheTypeTheOthersRequire() {
        // A: time only, B: both, C: neither. Time is supported by every constrained input; height is not (A).
        assertEquals(600_000_001L, locktimeOf(psbt(null, listOf(time(600_000_000)), listOf(height(100), time(600_000_001)), emptyList())))
    }

    @Test
    fun heightWinsWhenEveryConstrainedInputSupportsIt() {
        assertEquals(200L, locktimeOf(psbt(null, listOf(height(100), time(600_000_000)), listOf(height(200)))))
        assertEquals(300L, locktimeOf(psbt(null, listOf(height(300), time(600_000_000)), listOf(height(200), time(700_000_000)))))
    }

    @Test
    fun timeIsUsedWhenOnlyTimeIsCommon() {
        assertEquals(650_000_000L, locktimeOf(psbt(null, listOf(time(650_000_000)), listOf(height(1), time(600_000_000)))))
    }

    @Test
    fun incompatibleInputsAreRejectedNotSilentlyResolved() {
        assertRejected(psbt(null, listOf(height(100)), listOf(time(600_000_000))))
    }

    @Test
    fun fieldRangesAreEnforced() {
        assertRejected(psbt(null, listOf(height(0))))
        assertRejected(psbt(null, listOf(height(500_000_000))))
        assertRejected(psbt(null, listOf(time(499_999_999))))
        assertEquals(499_999_999L, locktimeOf(psbt(null, listOf(height(499_999_999)))))
        assertEquals(500_000_000L, locktimeOf(psbt(null, listOf(time(500_000_000)))))
        // Wrong width.
        assertRejected(psbt(null, listOf(DataEntry(ByteVector("12"), ByteVector("0102")))))
    }
}
