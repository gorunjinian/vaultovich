package com.gorunjinian.vaultovich

import com.gorunjinian.vaultovich.io.ByteArrayInput
import com.gorunjinian.vaultovich.io.ByteArrayOutput
import com.gorunjinian.vaultovich.utils.Either
import fr.acinq.secp256k1.Hex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Everything the device parses arrives from an untrusted host (QR codes, files). The parsers must
 * report malformed input through their `Either` result, never by throwing, and must not do
 * unbounded work before validation.
 */
class ParserHardeningTest {

    private val magic = Hex.decode("70736274ff")

    private fun varint(n: Int): ByteArray = ByteArrayOutput().also { BtcSerializer.writeVarint(n, it) }.toByteArray()
    private fun entry(key: ByteArray, value: ByteArray): ByteArray = varint(key.size) + key + varint(value.size) + value
    private val separator = byteArrayOf(0)

    private val key = DeterministicWallet.generate(ByteVector(ByteArray(32) { 9 })).derivePrivateKey(KeyPath("m/84'/1'/0'/0/0")).privateKey
    private val p2wpkh = Script.write(Script.pay2wpkh(key.publicKey()))
    private val unsignedTx = Transaction(
        2,
        listOf(TxIn(OutPoint(TxHash("ab".repeat(32)), 0), ByteVector.empty, TxIn.SEQUENCE_FINAL)),
        listOf(TxOut(Satoshi(90_000), ByteVector(p2wpkh))),
        0,
    )
    private val globalMap = entry(byteArrayOf(0x00), Transaction.write(unsignedTx, Transaction.SERIALIZE_TRANSACTION_NO_WITNESS)) + separator

    /** A one-input, one-output v0 PSBT whose input map is [inputEntries]. */
    private fun psbtWithInput(inputEntries: ByteArray): ByteArray = magic + globalMap + inputEntries + separator + separator

    private fun assertLeft(bytes: ByteArray): ParseFailure {
        val result = Psbt.read(bytes)
        assertTrue("expected Left, got $result", result is Either.Left)
        return (result as Either.Left).value
    }

    @Test
    fun keyLengthWiderThanIntIsReportedNotThrown() {
        // varint 0xFE FF FF FF FF = 4294967295, which narrowed to Int is -1.
        assertEquals(ParseFailure.InvalidContent, assertLeft(magic + Hex.decode("feffffffff")))
        assertEquals(ParseFailure.InvalidContent, assertLeft(magic + Hex.decode("fe00000080")))
    }

    @Test
    fun keyLengthBeyondAvailableBytesIsReported() {
        assertEquals(ParseFailure.InvalidContent, assertLeft(magic + byteArrayOf(0x10, 1, 2, 3)))
    }

    @Test
    fun truncatedAfterKeyIsReported() {
        assertEquals(ParseFailure.InvalidContent, assertLeft(magic + byteArrayOf(0x01, 0x00)))
    }

    @Test
    fun varintAtEndOfStreamFailsInsteadOfWrapping() {
        val e = runCatching { BtcSerializer.varint(ByteArrayInput(ByteArray(0))) }.exceptionOrNull()
        assertTrue("expected IllegalArgumentException, got $e", e is IllegalArgumentException)
    }

    @Test
    fun tensOfThousandsOfEntriesDoNotOverflowTheStack() {
        val out = ByteArrayOutput()
        out.write(magic)
        repeat(60_000) { i -> out.write(entry(byteArrayOf(0xfc.toByte()) + Hex.decode("%08x".format(i)), ByteArray(0))) }
        out.write(separator)
        // No unsigned tx in the global map, so the well-formed part of the parse fails on that.
        assertEquals(ParseFailure.GlobalTxMissing, assertLeft(out.toByteArray()))
    }

    @Test
    fun duplicateKeysAreStillRejected() {
        val dup = entry(byteArrayOf(0xfc.toByte(), 1), ByteArray(0))
        assertEquals(ParseFailure.DuplicateKeys, assertLeft(magic + dup + dup + separator))
    }

    @Test
    fun malformedTaprootDerivationIsReportedNotThrown() {
        val xonly = ByteArray(32) { 1 }
        // 65535 leaf hashes announced, none present.
        val bad = entry(byteArrayOf(0x16) + xonly, Hex.decode("fdffff"))
        assertTrue(assertLeft(psbtWithInput(bad)) is ParseFailure.InvalidTxInput)
        // Empty value.
        assertTrue(assertLeft(psbtWithInput(entry(byteArrayOf(0x16) + xonly, ByteArray(0)))) is ParseFailure.InvalidTxInput)
        // Trailing bytes that are not whole child indices.
        assertTrue(assertLeft(psbtWithInput(entry(byteArrayOf(0x16) + xonly, Hex.decode("00" + "deadbeef" + "0000")))) is ParseFailure.InvalidTxInput)
        // Well-formed: no leaves, fingerprint, one child index.
        val ok = entry(byteArrayOf(0x16) + xonly, Hex.decode("00" + "deadbeef" + "05000000"))
        assertTrue(Psbt.read(psbtWithInput(ok)) is Either.Right)
    }

    @Test
    fun witnessUtxoAmountOutOfRangeIsRejected() {
        val overMax = Hex.decode("ffffffffffffffff") + varint(p2wpkh.size) + p2wpkh
        assertTrue(assertLeft(psbtWithInput(entry(byteArrayOf(0x01), overMax))) is ParseFailure.InvalidTxInput)
        val justOverMax = ByteArrayOutput().also { BtcSerializer.writeUInt64((Satoshi.MAX_MONEY.sat + 1).toULong(), it) }.toByteArray() + varint(p2wpkh.size) + p2wpkh
        assertTrue(assertLeft(psbtWithInput(entry(byteArrayOf(0x01), justOverMax))) is ParseFailure.InvalidTxInput)
        val fine = TxOut.write(TxOut(Satoshi.MAX_MONEY, ByteVector(p2wpkh)))
        assertTrue(Psbt.read(psbtWithInput(entry(byteArrayOf(0x01), fine))) is Either.Right)
    }

    @Test
    fun satoshiArithmeticIsExact() {
        assertTrue(runCatching { Satoshi(Long.MAX_VALUE) + Satoshi(1) }.exceptionOrNull() is ArithmeticException)
        assertTrue(runCatching { Satoshi(Long.MIN_VALUE) - Satoshi(1) }.exceptionOrNull() is ArithmeticException)
        assertTrue(runCatching { Satoshi(Long.MAX_VALUE) * 2 }.exceptionOrNull() is ArithmeticException)
        assertEquals(Satoshi(3), Satoshi(1) + Satoshi(2))
    }

    @Test
    fun base58AddressWithWrongPayloadLengthIsLeftNotThrown() {
        val bogus = Base58Check.encode(Base58.Prefix.PubkeyAddress, ByteArray(21) { 7 })
        val result = Bitcoin.addressToPublicKeyScript(Block.LivenetGenesisBlock.hash, bogus)
        assertTrue("expected Left, got $result", result is Either.Left)
        val bogusP2sh = Base58Check.encode(Base58.Prefix.ScriptAddress, ByteArray(19) { 7 })
        assertTrue(Bitcoin.addressToPublicKeyScript(Block.LivenetGenesisBlock.hash, bogusP2sh) is Either.Left)
    }

    @Test
    fun transactionHashIsUnchangedByLazyEvaluation() {
        val hex = "0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300"
        val tx = Transaction.read(hex)
        val expected = TxHash(Crypto.hash256(Transaction.write(tx, Transaction.SERIALIZE_TRANSACTION_NO_WITNESS)))
        assertEquals(expected, tx.hash)
        assertEquals(TxId(expected), tx.txid)
        assertEquals(tx.hash, tx.copy(lockTime = tx.lockTime).hash)
        assertEquals(tx.txid, Transaction.read(Transaction.write(tx)).txid)
    }

    @Test
    fun truncatedTransactionFailsCleanly() {
        val bytes = Transaction.write(unsignedTx)
        for (n in 1 until bytes.size) {
            val e = runCatching { Transaction.read(bytes.copyOf(n)) }.exceptionOrNull()
            assertTrue("truncated at $n: expected IllegalArgumentException, got $e", e is IllegalArgumentException)
        }
    }
}
