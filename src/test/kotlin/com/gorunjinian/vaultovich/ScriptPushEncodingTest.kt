package com.gorunjinian.vaultovich

import fr.acinq.secp256k1.Hex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScriptPushEncodingTest {

    @Test
    fun pushesUseTheSmallestOpcode() {
        // Lengths 0xff and 0xffff fit in OP_PUSHDATA1 and OP_PUSHDATA2: using the next opcode is a non-minimal push,
        // which SCRIPT_VERIFY_MINIMALDATA (standardness policy) rejects.
        val expected = listOf(75 to 75, 76 to OP_PUSHDATA1.code, 255 to OP_PUSHDATA1.code, 256 to OP_PUSHDATA2.code, 65535 to OP_PUSHDATA2.code, 65536 to OP_PUSHDATA4.code)
        for ((size, code) in expected) {
            val push = OP_PUSHDATA(ByteArray(size) { 0x42 })
            assertEquals("push of $size bytes", code, push.code)
            assertTrue("push of $size bytes", OP_PUSHDATA.isMinimal(push.data.toByteArray(), push.code))
        }
        assertEquals("4cff", Hex.encode(Script.write(listOf(OP_PUSHDATA(ByteArray(255))))).take(4))
        assertEquals("4dffff", Hex.encode(Script.write(listOf(OP_PUSHDATA(ByteArray(65535))))).take(6))
    }

    @Test
    fun minimalPushChecks() {
        assertTrue(OP_PUSHDATA.isMinimal(ByteArray(0), OP_0.code))
        // Values 1..16 and 0x81 must be pushed with OP_1..OP_16 and OP_1NEGATE.
        assertFalse(OP_PUSHDATA.isMinimal(byteArrayOf(5), 1))
        assertFalse(OP_PUSHDATA.isMinimal(byteArrayOf(0x81.toByte()), 1))
        assertTrue(OP_PUSHDATA.isMinimal(byteArrayOf(17), 1))
        assertFalse(OP_PUSHDATA.isMinimal(ByteArray(255), OP_PUSHDATA2.code))
        assertFalse(OP_PUSHDATA.isMinimal(ByteArray(75), OP_PUSHDATA1.code))
    }

    @Test
    fun scriptWithA255BytePushPassesMinimalData() {
        // A script written by this library must satisfy MINIMALDATA, e.g. a 255-byte element followed by OP_DROP OP_1.
        val script = Script.write(listOf(OP_PUSHDATA(ByteArray(255) { 1 }), OP_DROP, OP_1))
        val tx = Transaction(2, listOf(TxIn(OutPoint(TxHash(ByteVector32.Zeroes), 0), ByteVector.empty, TxIn.SEQUENCE_FINAL)), listOf(TxOut(Satoshi(1000), ByteVector.empty)), 0)
        val runner = Script.Runner(Script.Context(tx, 0, Satoshi(0), listOf()), ScriptFlags.SCRIPT_VERIFY_MINIMALDATA)
        assertEquals(listOf(ByteVector("01")), runner.run(script, SigVersion.SIGVERSION_BASE))
    }
}
