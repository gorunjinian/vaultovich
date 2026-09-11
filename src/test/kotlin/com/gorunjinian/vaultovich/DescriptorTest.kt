package com.gorunjinian.vaultovich

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DescriptorTest {

    private val checksumChars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    /**
     * Checksums computed with Bitcoin Core's reference implementation
     * (`test/functional/test_framework/descriptors.py`, `descsum_create`). The `ggrsrxfy` case is
     * the vector from Core's own tests; `cjjspncu` is the example from Core's `doc/descriptors.md`.
     */
    @Test
    fun checksumMatchesBitcoinCore() {
        val xpub = "xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY"
        val vectors = mapOf(
            "sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))" to "ggrsrxfy",
            "pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)" to "9pcxlpvx",
            "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)" to "ah7klf29",
            "sh(wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))" to "0aua3a8r",
            "combo(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)" to "jjh3jqzg",
            "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)" to "dh4fyxrd",
            "wpkh([d34db33f/84h/0h/0h]$xpub/0/*)" to "cjjspncu",
            "wsh(sortedmulti(2,[d34db33f/48h/0h/0h/2h]$xpub/<0;1>/*,[00000001/48h/0h/0h/2h]$xpub/<0;1>/*))" to "fwhtwxqe",
        )
        for ((desc, expected) in vectors) assertEquals(desc, expected, Descriptor.checksum(desc))
    }

    @Test
    fun checksumRejectsCharactersOutsideTheDescriptorCharset() {
        for (bad in listOf("wpkh(é)", "wpkh(abc)\n", "wpkh( )")) {
            val e = runCatching { Descriptor.checksum(bad) }.exceptionOrNull()
            assertTrue("expected IllegalArgumentException for ${fr.acinq.secp256k1.Hex.encode(bad.toByteArray())}, got $e", e is IllegalArgumentException)
            assertTrue(e!!.message!!.contains("position"))
        }
    }

    private fun master(seedByte: Int) = DeterministicWallet.generate(ByteVector(ByteArray(32) { seedByte.toByte() }))

    @Test
    fun bip84DescriptorsUseTheAccountLevelKeyAndAPaddedFingerprint() {
        // Find a seed whose fingerprint has a leading zero nibble, the case the old code got wrong.
        val m = (1..200).map { master(it) }.first { DeterministicWallet.fingerprint(it) < 0x10000000L }
        val fp = DeterministicWallet.fingerprint(m)
        val (receive, change) = Descriptor.BIP84Descriptors(Block.Testnet3GenesisBlock.hash, m)

        val re = Regex("""^wpkh\(\[([0-9a-f]{8})/84'/1'/0'](tpub[1-9A-HJ-NP-Za-km-z]+)/([01])/\*\)#([$checksumChars]{8})$""")
        val r = re.matchEntire(receive) ?: error("unexpected receive descriptor: $receive")
        val c = re.matchEntire(change) ?: error("unexpected change descriptor: $change")
        assertEquals(Descriptor.formatFingerprint(fp), r.groupValues[1])
        assertEquals("0", r.groupValues[3])
        assertEquals("1", c.groupValues[3])

        // The embedded key is the account key at m/84'/1'/0' (depth 3), not one level deeper.
        val (_, embedded) = DeterministicWallet.ExtendedPublicKey.decode(r.groupValues[2])
        val account = DeterministicWallet.publicKey(m.derivePrivateKey(KeyPath("m/84'/1'/0'")))
        assertEquals(3, embedded.depth)
        assertEquals(account.publickeybytes, embedded.publickeybytes)
        assertEquals(account.chaincode, embedded.chaincode)

        // Checksum covers the body exactly.
        assertEquals(r.groupValues[4], Descriptor.checksum(receive.substringBefore('#')))
    }

    @Test
    fun bip84MainnetUsesCoinType0AndXpub() {
        val (receive, _) = Descriptor.BIP84Descriptors(Block.LivenetGenesisBlock.hash, master(3))
        assertTrue(receive, receive.startsWith("wpkh([") && receive.contains("/84'/0'/0']xpub"))
    }

    @Test
    fun slip132PrefixesEncodeWithTheExpectedLetters() {
        // The first characters of a Base58Check string are fixed by the version bytes, so this
        // pins the SLIP-132 constants without relying on an external vector.
        val key = DeterministicWallet.publicKey(master(4).derivePrivateKey(KeyPath("m/48'/0'/0'/2'")))
        val expected = mapOf(
            DeterministicWallet.xpub to "xpub", DeterministicWallet.ypub to "ypub", DeterministicWallet.zpub to "zpub",
            DeterministicWallet.Ypub to "Ypub", DeterministicWallet.Zpub to "Zpub",
            DeterministicWallet.tpub to "tpub", DeterministicWallet.upub to "upub", DeterministicWallet.vpub to "vpub",
            DeterministicWallet.Upub to "Upub", DeterministicWallet.Vpub to "Vpub",
        )
        for ((prefix, letters) in expected) {
            val encoded = DeterministicWallet.encode(key, prefix)
            assertTrue("$letters: $encoded", encoded.startsWith(letters))
            // And every one of them decodes again.
            assertEquals(prefix, DeterministicWallet.ExtendedPublicKey.decode(encoded).first)
        }
    }

    @Test
    fun extendedKeysAreNormalisedToXpubOrTpub() {
        val key = DeterministicWallet.publicKey(master(5).derivePrivateKey(KeyPath("m/48'/0'/0'/2'")))
        val xpub = DeterministicWallet.encode(key, DeterministicWallet.xpub)
        val tpub = DeterministicWallet.encode(key, DeterministicWallet.tpub)
        for (p in listOf(DeterministicWallet.xpub, DeterministicWallet.ypub, DeterministicWallet.zpub, DeterministicWallet.Ypub, DeterministicWallet.Zpub)) {
            assertEquals(xpub, Descriptor.normalizeExtendedPublicKey(DeterministicWallet.encode(key, p)))
        }
        for (p in listOf(DeterministicWallet.tpub, DeterministicWallet.upub, DeterministicWallet.vpub, DeterministicWallet.Upub, DeterministicWallet.Vpub)) {
            assertEquals(tpub, Descriptor.normalizeExtendedPublicKey(DeterministicWallet.encode(key, p)))
        }
    }

    @Test
    fun privateAndMalformedKeysAreRefused() {
        val priv = master(6).derivePrivateKey(KeyPath("m/84'/0'/0'"))
        for (p in listOf(DeterministicWallet.xprv, DeterministicWallet.zprv, DeterministicWallet.Zprv, DeterministicWallet.tprv, DeterministicWallet.Vprv)) {
            val e = runCatching { Descriptor.normalizeExtendedPublicKey(DeterministicWallet.encode(priv, p)) }.exceptionOrNull()
            assertTrue("prefix $p: $e", e is IllegalArgumentException && e.message!!.contains("private"))
        }
        assertTrue(runCatching { Descriptor.normalizeExtendedPublicKey("xpub-not-a-key") }.exceptionOrNull() is IllegalArgumentException)
        assertTrue(runCatching { Descriptor.normalizeExtendedPublicKey("") }.exceptionOrNull() is IllegalArgumentException)
    }

    @Test
    fun unifiedDescriptorNormalisesSlip132Input() {
        val m = master(7)
        val account = DeterministicWallet.publicKey(m.derivePrivateKey(KeyPath("m/84'/0'/0'")))
        val zpub = DeterministicWallet.encode(account, DeterministicWallet.zpub)
        val xpub = DeterministicWallet.encode(account, DeterministicWallet.xpub)
        val fp = DeterministicWallet.fingerprint(m)
        val desc = DescriptorExtensions.getUnifiedDescriptor(fp, "m/84'/0'/0'", zpub, ScriptType.P2WPKH)
        assertEquals("wpkh([${Descriptor.formatFingerprint(fp)}/84h/0h/0h]$xpub/<0;1>/*)", desc.substringBefore('#'))
        assertEquals(Descriptor.checksum(desc.substringBefore('#')), desc.substringAfter('#'))
    }

    @Test
    fun bip48DescriptorWrapsSortedMultiInWsh() {
        val masters = listOf(master(11), master(12), master(13))
        val cosigners = masters.map { m ->
            val account = DeterministicWallet.publicKey(m.derivePrivateKey(KeyPath("m/48'/0'/0'/2'")))
            DescriptorExtensions.CosignerKey(DeterministicWallet.fingerprint(m), "m/48'/0'/0'/2'", DeterministicWallet.encode(account, DeterministicWallet.Zpub))
        }
        val expectedKeys = masters.joinToString(",") { m ->
            val account = DeterministicWallet.publicKey(m.derivePrivateKey(KeyPath("m/48'/0'/0'/2'")))
            "[${Descriptor.formatFingerprint(DeterministicWallet.fingerprint(m))}/48h/0h/0h/2h]${DeterministicWallet.encode(account, DeterministicWallet.xpub)}/<0;1>/*"
        }

        val native = DescriptorExtensions.getBip48Descriptor(2, cosigners)
        assertEquals("wsh(sortedmulti(2,$expectedKeys))", native.substringBefore('#'))
        assertEquals(Descriptor.checksum(native.substringBefore('#')), native.substringAfter('#'))

        val wrapped = DescriptorExtensions.getBip48Descriptor(2, cosigners, isWrapped = true)
        assertEquals("sh(wsh(sortedmulti(2,$expectedKeys)))", wrapped.substringBefore('#'))

        val unsorted = DescriptorExtensions.getBip48Descriptor(3, cosigners, sortedKeys = false)
        assertEquals("wsh(multi(3,$expectedKeys))", unsorted.substringBefore('#'))

        // A single cosigner's contribution is a key expression, never a bare key inside wsh().
        val mine = DescriptorExtensions.getBip48KeyExpression(cosigners[0].fingerprint, cosigners[0].derivationPath, cosigners[0].extendedKey)
        assertEquals(expectedKeys.split(",")[0].removeSuffix("/<0;1>/*"), mine)

        assertTrue(runCatching { DescriptorExtensions.getBip48Descriptor(4, cosigners) }.isFailure)
        assertTrue(runCatching { DescriptorExtensions.getBip48Descriptor(0, cosigners) }.isFailure)
        assertTrue(runCatching { DescriptorExtensions.getBip48Descriptor(1, emptyList()) }.isFailure)
    }
}
