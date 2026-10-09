package com.gorunjinian.vaultovich

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScriptWitnessConsensusTest {

    private val tx = Transaction(2, listOf(TxIn(OutPoint(TxHash(ByteVector32.Zeroes), 0), ByteVector.empty, TxIn.SEQUENCE_FINAL)), listOf(TxOut(Satoshi(1000), ByteVector.empty)), 0)
    private val flags = ScriptFlags.SCRIPT_VERIFY_P2SH or ScriptFlags.SCRIPT_VERIFY_WITNESS

    private fun verify(scriptSig: String, scriptPubKey: String, witness: List<String>, scriptFlags: Int = flags): Result<Boolean> = runCatching {
        Script.Runner(Script.Context(tx, 0, Satoshi(0), listOf()), scriptFlags)
            .verifyScripts(ByteVector(scriptSig).toByteArray(), ByteVector(scriptPubKey).toByteArray(), ScriptWitness(witness.map { ByteVector(it) }))
    }

    // P2SH(P2WSH(OP_1)): the redeem script is the witness program 0020 || sha256(51).
    private val p2wshProgram = "00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260"
    private val p2shOfP2wsh = "a91472c44f957fc011d97e3406667dca5b1c930c402687"

    @Test
    fun p2shWrappedWitnessRequiresAnExactRedeemScriptPush() {
        assertTrue(verify("22$p2wshProgram", p2shOfP2wsh, listOf("51")).getOrThrow())
        // BIP-141: the scriptSig must be exactly a push of the redeem script. These spends are consensus-invalid
        // (WITNESS_MALLEATED_P2SH) but used to be accepted.
        assertFalse(verify("0022$p2wshProgram", p2shOfP2wsh, listOf("51")).getOrDefault(false))
        assertFalse(verify("4c22$p2wshProgram", p2shOfP2wsh, listOf("51")).getOrDefault(false))
    }

    @Test
    fun p2wshWithAnEmptyWitnessFailsCleanly() {
        val result = verify("", p2wshProgram, listOf())
        assertTrue(result.exceptionOrNull() is IllegalArgumentException)
    }

    @Test
    fun p2aCanBeSpentWithAnyWitness() {
        // An empty witness for pay-to-anchor is a standardness rule, not a consensus rule.
        assertTrue(verify("", "51024e73", listOf()).getOrThrow())
        assertTrue(verify("", "51024e73", listOf("deadbeef")).getOrThrow())
    }
}
