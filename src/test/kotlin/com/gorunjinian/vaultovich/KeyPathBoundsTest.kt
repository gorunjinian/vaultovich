package com.gorunjinian.vaultovich

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** BIP-32 child indices are 32-bit; hardened indices are 0 .. 2^31 - 1 before the offset. */
class KeyPathBoundsTest {

    private val master = DeterministicWallet.generate(ByteVector(ByteArray(32) { 41 }))

    private fun assertRejected(block: () -> Any?) {
        val e = runCatching(block).exceptionOrNull()
        assertTrue("expected IllegalArgumentException, got $e", e is IllegalArgumentException)
    }

    @Test
    fun pathsOutsideTheRangeAreRejected() {
        assertRejected { KeyPath("m/2147483648'") }   // would wrap to child 0 on the wire
        assertRejected { KeyPath("m/2147483648") }    // non-hardened notation above 2^31 - 1
        assertRejected { KeyPath("m/-1") }
        assertRejected { KeyPath("m//0") }
        assertRejected { KeyPath(listOf(4_294_967_296L)) }
        assertRejected { KeyPath(listOf(-1L)) }
        assertRejected { DeterministicWallet.hardened(0x80000000L) }
        assertRejected { DeterministicWallet.hardened(-1) }
    }

    @Test
    fun boundaryValuesAreAccepted() {
        assertEquals(listOf(0xFFFFFFFFL), KeyPath("m/2147483647'").path)
        assertEquals(listOf(0xFFFFFFFFL), KeyPath("m/2147483647h").path)
        assertEquals(listOf(0x7FFFFFFFL), KeyPath("m/2147483647").path)
        assertEquals(listOf(0x80000000L, 0L), KeyPath("m/0'/0").path)
        assertEquals("m/2147483647'", KeyPath("m/2147483647'").toString())
        assertEquals(KeyPath.empty, KeyPath("m"))
    }

    @Test
    fun derivationRejectsOutOfRangeIndices() {
        assertRejected { master.derivePrivateKey(-1L) }
        assertRejected { master.derivePrivateKey(0x1_0000_0000L) }
        master.derivePrivateKey(0xFFFFFFFFL)
        val pub = master.extendedPublicKey
        assertRejected { pub.derivePublicKey(-1L) }
        assertRejected { pub.derivePublicKey(0x1_0000_0000L) }
        assertRejected { pub.derivePublicKey(0x80000000L) } // hardened from a public key
        pub.derivePublicKey(0x7FFFFFFFL)
    }
}
