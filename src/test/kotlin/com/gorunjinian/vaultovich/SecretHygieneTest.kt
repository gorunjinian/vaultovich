package com.gorunjinian.vaultovich

import fr.acinq.secp256k1.Hex
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Exception messages must never carry key material: they reach logcat and crash reporters. */
class SecretHygieneTest {

    private fun messageOf(block: () -> Any?): String = runCatching(block).exceptionOrNull()?.message ?: ""

    @Test
    fun base58CheckFailureDoesNotEchoTheInput() {
        // A mainnet WIF with one corrupted character: the most common import mistake.
        val typo = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTX"
        val msg = messageOf { Base58Check.decode(typo) }
        assertTrue(msg.isNotEmpty())
        assertFalse(msg.contains(typo.substring(5, 20)))
        val msg2 = messageOf { Base58Check.decodeWithPrefixLen(typo, 4) }
        assertTrue(msg2.isNotEmpty())
        assertFalse(msg2.contains(typo.substring(5, 20)))
    }

    @Test
    fun base58CheckShortInputFailsCleanly() {
        for (s in listOf("", "1", "1111")) {
            val e = runCatching { Base58Check.decode(s) }.exceptionOrNull()
            assertTrue("expected IllegalArgumentException for '$s', got $e", e is IllegalArgumentException)
        }
    }

    @Test
    fun privateKeyLengthFailureDoesNotEchoTheBytes() {
        val bytes = ByteArray(34) { 0x5a }
        val msg = messageOf { PrivateKey.isCompressed(bytes) }
        assertTrue(msg.isNotEmpty())
        assertFalse(msg.contains(Hex.encode(bytes).substring(0, 16)))
    }

    @Test
    fun invalidMnemonicWordIsNotEchoed() {
        val words = ("abandon ".repeat(11) + "zzzzzz").split(" ")
        val msg = messageOf { MnemonicCode.validate(words) }
        assertTrue(msg.contains("position 12"))
        assertFalse(msg.contains("zzzzzz"))
        assertFalse(msg.contains("abandon"))
    }

    @Test
    fun wrongWifPrefixMessageOnlyNamesThePrefix() {
        val priv = PrivateKey(ByteArray(32) { 1 })
        val testnetWif = priv.toBase58(Base58.Prefix.SecretKeyTestnet)
        val msg = messageOf { PrivateKey.fromBase58(testnetWif, Base58.Prefix.SecretKey) }
        assertTrue(msg.isNotEmpty())
        assertFalse(msg.contains(testnetWif.substring(5, 20)))
        assertFalse(msg.contains(priv.toHex().substring(0, 16)))
    }
}
