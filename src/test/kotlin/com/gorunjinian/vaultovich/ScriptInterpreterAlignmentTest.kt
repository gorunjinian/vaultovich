package com.gorunjinian.vaultovich

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Interpreter rules aligned with Bitcoin Core (bitcoin-kmp #189, #191) that neither Core's script_tests.json nor
 * upstream's extra script vectors exercise.
 */
class ScriptInterpreterAlignmentTest {

    private val tx = Transaction(2, listOf(TxIn(OutPoint(TxHash(ByteVector32.Zeroes), 0), ByteVector.empty, TxIn.SEQUENCE_FINAL)), listOf(TxOut(Satoshi(1000), ByteVector.empty)), 0)
    private val priv = PrivateKey(ByteVector32("0101010101010101010101010101010101010101010101010101010101010101"))

    private fun runner(flags: Int) = Script.Runner(Script.Context(tx, 0, Satoshi(0), listOf()), flags)

    private fun verify(scriptSig: List<ScriptElt>, scriptPubKey: List<ScriptElt>, flags: Int): Result<Boolean> = runCatching {
        runner(flags).verifyScripts(Script.write(scriptSig), Script.write(scriptPubKey), ScriptWitness.empty)
    }

    @Test
    fun checkLockTimeAndCheckSequenceAreNopsWhenTheirFlagIsUnset() {
        // As in Core, DISCOURAGE_UPGRADABLE_NOPS does not apply to NOP2 / NOP3 once they are CLTV / CSV.
        for (op in listOf(OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY)) {
            assertEquals(listOf(ByteVector("01")), runner(ScriptFlags.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS).run(listOf(OP_1, op), listOf(), SigVersion.SIGVERSION_BASE))
        }
        assertTrue(runCatching { runner(ScriptFlags.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY).run(listOf(OP_CHECKLOCKTIMEVERIFY), listOf(), SigVersion.SIGVERSION_BASE) }.exceptionOrNull() is IllegalArgumentException)
    }

    @Test
    fun emptySignatureIsCheckedAfterThePublicKeyEncoding() {
        // An empty signature with a malformed public key fails the script under STRICTENC, instead of making CHECKSIG
        // return false (which OP_NOT turns into success).
        val scriptPubKey = listOf(OP_PUSHDATA(byteArrayOf(0)), OP_CHECKSIG, OP_NOT)
        assertTrue(verify(listOf(OP_0), scriptPubKey, ScriptFlags.SCRIPT_VERIFY_P2SH).getOrThrow())
        assertTrue(verify(listOf(OP_0), scriptPubKey, ScriptFlags.SCRIPT_VERIFY_P2SH or ScriptFlags.SCRIPT_VERIFY_STRICTENC).isFailure)
    }

    @Test
    fun signaturesCommitToTheScriptAfterTheLastExecutedCodeSeparator() {
        val tail = listOf(OP_PUSHDATA(priv.publicKey().value), OP_CHECKSIG)
        fun sig(scriptCode: List<ScriptElt>) = listOf(OP_PUSHDATA(Transaction.signInput(tx, 0, scriptCode, SigHash.SIGHASH_ALL, priv)))

        val executed = listOf(OP_1, OP_DROP, OP_CODESEPARATOR) + tail
        assertTrue(verify(sig(tail), executed, ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS).getOrThrow())
        assertTrue(verify(sig(executed), executed, ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS).isFailure)

        // A separator in a branch that is not executed does not move the script code.
        val skipped = listOf(OP_0, OP_IF, OP_CODESEPARATOR, OP_ENDIF) + tail
        assertTrue(verify(sig(skipped), skipped, ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS).getOrThrow())
        assertTrue(verify(sig(tail), skipped, ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS).isFailure)
    }

    @Test
    fun inconsistentFlagCombinationsAreRejected() {
        // As in Core, CLEANSTACK requires P2SH and WITNESS, and WITNESS requires P2SH.
        val ok = listOf(OP_1)
        for (flags in listOf(ScriptFlags.SCRIPT_VERIFY_P2SH or ScriptFlags.SCRIPT_VERIFY_CLEANSTACK, ScriptFlags.SCRIPT_VERIFY_WITNESS)) {
            assertTrue(verify(listOf(), ok, flags).exceptionOrNull() is IllegalArgumentException)
        }
        assertTrue(verify(listOf(), ok, ScriptFlags.SCRIPT_VERIFY_P2SH or ScriptFlags.SCRIPT_VERIFY_WITNESS or ScriptFlags.SCRIPT_VERIFY_CLEANSTACK).getOrThrow())
    }
}
