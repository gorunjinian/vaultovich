package com.gorunjinian.vaultovich

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScriptConditionStackTest {

    private val tx = Transaction(2, listOf(TxIn(OutPoint(TxHash(ByteVector32.Zeroes), 0), ByteVector.empty, TxIn.SEQUENCE_FINAL)), listOf(TxOut(Satoshi(1000), ByteVector.empty)), 0)

    private fun run(script: List<ScriptElt>, signatureVersion: Int = SigVersion.SIGVERSION_TAPSCRIPT): List<ByteVector> =
        Script.Runner(Script.Context(tx, 0, Satoshi(0), listOf()), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS).run(script, listOf(), signatureVersion)

    // Tapscript has no opcode limit, so IF nesting is only bounded by the witness size. Scanning the whole condition
    // stack on every opcode took ~28s for this 300 KB script on a desktop JVM; it must be linear.
    @Test(timeout = 10_000)
    fun deeplyNestedIfIsLinear() {
        val n = 100_000
        val script = List(n) { listOf(OP_1, OP_IF) }.flatten() + List(n) { OP_ENDIF } + OP_1
        assertEquals(listOf(ByteVector("01")), run(script))
    }

    @Test
    fun branchSelection() {
        // OP_1 IF 2 ELSE 3 ENDIF -> 2; OP_0 IF 2 ELSE 3 ENDIF -> 3; a false outer branch skips inner ones.
        assertEquals(listOf(ByteVector("02")), run(listOf(OP_1, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF)))
        assertEquals(listOf(ByteVector("03")), run(listOf(OP_0, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF)))
        assertEquals(listOf(ByteVector("05")), run(listOf(OP_0, OP_IF, OP_1, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF, OP_ELSE, OP_5, OP_ENDIF)))
        assertEquals(listOf(ByteVector("03")), run(listOf(OP_1, OP_IF, OP_0, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF, OP_ELSE, OP_5, OP_ENDIF)))
        // ELSE may be repeated: each one flips the branch.
        assertEquals(listOf(ByteVector("04")), run(listOf(OP_1, OP_IF, OP_ELSE, OP_ELSE, OP_4, OP_ENDIF)))
        for (unbalanced in listOf(listOf(OP_1, OP_IF), listOf(OP_ENDIF), listOf(OP_ELSE), listOf(OP_1, OP_IF, OP_ENDIF, OP_ENDIF))) {
            assertTrue(runCatching { run(unbalanced) }.isFailure)
        }
    }
}
