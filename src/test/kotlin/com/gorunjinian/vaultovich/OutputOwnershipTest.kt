package com.gorunjinian.vaultovich

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Change-output verification: an output is ours only when the script we rebuild from our own
 * account xpub at the declared path equals the output's actual scriptPubKey. A host-supplied
 * fingerprint, key or path proves nothing on its own.
 */
class OutputOwnershipTest {

    private fun master(seedByte: Int) = DeterministicWallet.generate(ByteVector(ByteArray(32) { seedByte.toByte() }))

    private val master = master(1)
    private val fingerprint = DeterministicWallet.fingerprint(master)

    private fun account(path: String, type: ScriptType) = SingleSigAccount(
        masterFingerprint = fingerprint,
        accountPath = KeyPath(path),
        accountKey = DeterministicWallet.publicKey(master.derivePrivateKey(KeyPath(path))),
        scriptType = type,
    )

    private val wpkh = account("m/84'/1'/0'", ScriptType.P2WPKH)
    private val tr = account("m/86'/1'/0'", ScriptType.P2TR)
    private val shWpkh = account("m/49'/1'/0'", ScriptType.P2SH_P2WPKH)
    private val pkh = account("m/44'/1'/0'", ScriptType.P2PKH)

    private fun pubAt(path: String): PublicKey = master.derivePrivateKey(KeyPath(path)).publicKey

    private fun entry(pub: PublicKey, fp: Long, path: String) = pub to KeyPathWithMaster(fp, KeyPath(path))

    private fun output(
        script: List<ScriptElt>,
        derivations: Map<PublicKey, KeyPathWithMaster> = emptyMap(),
        taproot: Map<XonlyPublicKey, TaprootBip32DerivationPath> = emptyMap(),
    ): Psbt {
        val tx = Transaction(
            2,
            listOf(TxIn(OutPoint(TxHash("aa".repeat(32)), 0), ByteVector.empty, TxIn.SEQUENCE_FINAL)),
            listOf(TxOut(Satoshi(10_000), ByteVector(Script.write(script)))),
            0,
        )
        val input = Input.PartiallySignedInputWithoutUtxo(null, emptyMap(), emptySet(), emptySet(), emptySet(), emptySet(), null, emptyMap(), null, emptyList())
        val out = Output.WitnessOutput(null, null, derivations, null, taproot, emptyList())
        return Psbt(Global(0, tx, emptyList(), emptyList()), listOf(input), listOf(out))
    }

    // ------------------------------------------------------------------------------ single-sig

    @Test
    fun p2wpkhChangeIsOurs() {
        val pub = pubAt("m/84'/1'/0'/1/5")
        val psbt = output(Script.pay2wpkh(pub), mapOf(entry(pub, fingerprint, "m/84'/1'/0'/1/5")))
        val result = psbt.verifyOutput(0, wpkh)
        assertEquals(OutputOwnership.Ours(1, 5), result)
        assertTrue((result as OutputOwnership.Ours).isChange)
    }

    @Test
    fun p2wpkhReceiveIsOursButNotChange() {
        val pub = pubAt("m/84'/1'/0'/0/0")
        val psbt = output(Script.pay2wpkh(pub), mapOf(entry(pub, fingerprint, "m/84'/1'/0'/0/0")))
        val result = psbt.verifyOutput(0, wpkh) as OutputOwnership.Ours
        assertEquals(0L, result.branch)
        assertTrue(!result.isChange)
    }

    @Test
    fun outputWithoutOurFingerprintIsExternal() {
        val other = master(2)
        val pub = other.derivePrivateKey(KeyPath("m/84'/1'/0'/0/0")).publicKey
        val psbt = output(Script.pay2wpkh(pub), mapOf(entry(pub, DeterministicWallet.fingerprint(other), "m/84'/1'/0'/0/0")))
        assertEquals(OutputOwnership.External, psbt.verifyOutput(0, wpkh))
        assertEquals(OutputOwnership.External, output(Script.pay2wpkh(pub)).verifyOutput(0, wpkh))
    }

    @Test
    fun ourFingerprintOnAForeignKeyIsAMismatch() {
        // The classic attack: the host pays its own key and stamps our fingerprint and a plausible path on it.
        val attacker = master(3).derivePrivateKey(KeyPath("m/84'/1'/0'/1/0")).publicKey
        val psbt = output(Script.pay2wpkh(attacker), mapOf(entry(attacker, fingerprint, "m/84'/1'/0'/1/0")))
        assertTrue(psbt.verifyOutput(0, wpkh) is OutputOwnership.Mismatch)
    }

    @Test
    fun ourKeyWithTheWrongScriptTypeIsAMismatch() {
        // Signable by us, but a P2WPKH wallet would never find it.
        val pub = pubAt("m/84'/1'/0'/1/0")
        val psbt = output(Script.pay2pkh(pub), mapOf(entry(pub, fingerprint, "m/84'/1'/0'/1/0")))
        assertTrue(psbt.verifyOutput(0, wpkh) is OutputOwnership.Mismatch)
    }

    @Test
    fun scriptPayingADifferentKeyThanDeclaredIsAMismatch() {
        val declared = pubAt("m/84'/1'/0'/1/0")
        val paid = master(3).derivePrivateKey(KeyPath("m/84'/1'/0'/1/0")).publicKey
        val psbt = output(Script.pay2wpkh(paid), mapOf(entry(declared, fingerprint, "m/84'/1'/0'/1/0")))
        assertTrue(psbt.verifyOutput(0, wpkh) is OutputOwnership.Mismatch)
    }

    @Test
    fun pathsOutsideTheAccountAreMismatches() {
        for (path in listOf("m/84'/1'/1'/1/0", "m/84'/1'/0'/2/0", "m/84'/1'/0'/1/0'", "m/84'/1'/0'/1", "m/84'/1'/0'/1/0/0")) {
            val pub = pubAt(path)
            val psbt = output(Script.pay2wpkh(pub), mapOf(entry(pub, fingerprint, path)))
            assertTrue("expected Mismatch for $path", psbt.verifyOutput(0, wpkh) is OutputOwnership.Mismatch)
        }
    }

    @Test
    fun extraForeignEntriesDoNotAffectTheDecision() {
        val pub = pubAt("m/84'/1'/0'/1/7")
        val foreign = master(2).derivePrivateKey(KeyPath("m/84'/1'/0'/1/7")).publicKey
        val psbt = output(
            Script.pay2wpkh(pub),
            mapOf(entry(foreign, 0x12345678L, "m/84'/1'/0'/1/7"), entry(pub, fingerprint, "m/84'/1'/0'/1/7")),
        )
        assertEquals(OutputOwnership.Ours(1, 7), psbt.verifyOutput(0, wpkh))
    }

    @Test
    fun nestedSegwitAndLegacyAccounts() {
        val p49 = pubAt("m/49'/1'/0'/1/2")
        val nested = output(Script.pay2sh(Script.pay2wpkh(p49)), mapOf(entry(p49, fingerprint, "m/49'/1'/0'/1/2")))
        assertEquals(OutputOwnership.Ours(1, 2), nested.verifyOutput(0, shWpkh))
        // Same key, bare P2WPKH script: not what a BIP-49 wallet scans.
        assertTrue(output(Script.pay2wpkh(p49), mapOf(entry(p49, fingerprint, "m/49'/1'/0'/1/2"))).verifyOutput(0, shWpkh) is OutputOwnership.Mismatch)

        val p44 = pubAt("m/44'/1'/0'/0/9")
        val legacy = output(Script.pay2pkh(p44), mapOf(entry(p44, fingerprint, "m/44'/1'/0'/0/9")))
        assertEquals(OutputOwnership.Ours(0, 9), legacy.verifyOutput(0, pkh))
    }

    // --------------------------------------------------------------------------------- taproot

    private fun tapEntry(xonly: XonlyPublicKey, fp: Long, path: String, leaves: List<ByteVector32> = emptyList()) =
        xonly to TaprootBip32DerivationPath(leaves, fp, KeyPath(path))

    @Test
    fun taprootChangeIsOurs() {
        val internal = pubAt("m/86'/1'/0'/1/3").xOnly()
        val psbt = output(Script.pay2tr(internal, null as ByteVector32?), taproot = mapOf(tapEntry(internal, fingerprint, "m/86'/1'/0'/1/3")))
        assertEquals(OutputOwnership.Ours(1, 3), psbt.verifyOutput(0, tr))
    }

    @Test
    fun taprootWithUntweakedKeyOrScriptPathsIsAMismatch() {
        val internal = pubAt("m/86'/1'/0'/1/3").xOnly()
        // Output key equals the internal key: not a BIP-86 output, could hide a script tree we do not know.
        val untweaked = output(Script.pay2tr(internal), taproot = mapOf(tapEntry(internal, fingerprint, "m/86'/1'/0'/1/3")))
        assertTrue(untweaked.verifyOutput(0, tr) is OutputOwnership.Mismatch)
        // Leaf hashes declared: our key participates in a script path, which is not our single-sig account.
        val leaf = ByteVector32(ByteArray(32) { 4 })
        val withLeaves = output(Script.pay2tr(internal, null as ByteVector32?), taproot = mapOf(tapEntry(internal, fingerprint, "m/86'/1'/0'/1/3", listOf(leaf))))
        assertTrue(withLeaves.verifyOutput(0, tr) is OutputOwnership.Mismatch)
        // Attacker's internal key stamped with our fingerprint.
        val attacker = master(3).derivePrivateKey(KeyPath("m/86'/1'/0'/1/3")).publicKey.xOnly()
        val foreign = output(Script.pay2tr(attacker, null as ByteVector32?), taproot = mapOf(tapEntry(attacker, fingerprint, "m/86'/1'/0'/1/3")))
        assertTrue(foreign.verifyOutput(0, tr) is OutputOwnership.Mismatch)
        // No taproot entries at all.
        assertEquals(OutputOwnership.External, output(Script.pay2tr(internal, null as ByteVector32?)).verifyOutput(0, tr))
    }

    // -------------------------------------------------------------------------------- multisig

    private val cosignerMasters = listOf(master(1), master(2), master(3))
    private fun cosigner(m: DeterministicWallet.ExtendedPrivateKey) = Cosigner(
        DeterministicWallet.fingerprint(m), KeyPath("m/48'/1'/0'/2'"), DeterministicWallet.publicKey(m.derivePrivateKey(KeyPath("m/48'/1'/0'/2'"))),
    )
    private val multisig = MultisigAccount(2, cosignerMasters.map { cosigner(it) }, MultisigScriptType.P2WSH)

    private fun cosignerKeys(branch: Long, index: Long): List<PublicKey> =
        cosignerMasters.map { it.derivePrivateKey(KeyPath("m/48'/1'/0'/2'/$branch/$index")).publicKey }

    private fun multisigEntries(branch: Long, index: Long): Map<PublicKey, KeyPathWithMaster> =
        cosignerMasters.zip(cosignerKeys(branch, index)).associate { (m, pub) -> entry(pub, DeterministicWallet.fingerprint(m), "m/48'/1'/0'/2'/$branch/$index") }

    private fun sortedMulti(keys: List<PublicKey>) = Script.createMultiSigMofN(2, keys.sortedBy { it.value.toHex() })

    @Test
    fun sortedMultisigChangeIsOurs() {
        val psbt = output(Script.pay2wsh(sortedMulti(cosignerKeys(1, 4))), multisigEntries(1, 4))
        assertEquals(OutputOwnership.Ours(1, 4), psbt.verifyOutput(0, multisig))
        val nested = output(Script.pay2sh(Script.pay2wsh(sortedMulti(cosignerKeys(0, 1)))), multisigEntries(0, 1))
        assertEquals(OutputOwnership.Ours(0, 1), nested.verifyOutput(0, multisig.copy(scriptType = MultisigScriptType.P2SH_P2WSH)))
    }

    @Test
    fun multisigWithASwappedCosignerIsAMismatch() {
        // The host replaces cosigner 3's key with its own, keeps our two real keys, and builds a
        // valid-looking 2-of-3 that it can spend together with... itself, if we ever co-sign.
        val real = cosignerKeys(1, 0)
        val attacker = master(9).derivePrivateKey(KeyPath("m/48'/1'/0'/2'/1/0")).publicKey
        val swapped = listOf(real[0], real[1], attacker)
        val entries = multisigEntries(1, 0).filterKeys { it != real[2] } + entry(attacker, DeterministicWallet.fingerprint(cosignerMasters[2]), "m/48'/1'/0'/2'/1/0")
        val psbt = output(Script.pay2wsh(sortedMulti(swapped)), entries)
        assertTrue(psbt.verifyOutput(0, multisig) is OutputOwnership.Mismatch)
    }

    @Test
    fun multisigWithInconsistentChildPathsIsAMismatch() {
        val entries = multisigEntries(1, 0).toMutableMap()
        val k2 = cosignerKeys(1, 0)[1]
        entries[k2] = KeyPathWithMaster(DeterministicWallet.fingerprint(cosignerMasters[1]), KeyPath("m/48'/1'/0'/2'/1/1"))
        val psbt = output(Script.pay2wsh(sortedMulti(cosignerKeys(1, 0))), entries)
        assertTrue(psbt.verifyOutput(0, multisig) is OutputOwnership.Mismatch)
    }

    @Test
    fun multisigWithWrongThresholdOrOrderIsAMismatch() {
        val keys = cosignerKeys(0, 0)
        val oneOfThree = output(Script.pay2wsh(Script.createMultiSigMofN(1, keys.sortedBy { it.value.toHex() })), multisigEntries(0, 0))
        assertTrue(oneOfThree.verifyOutput(0, multisig) is OutputOwnership.Mismatch)
        val unsorted = output(Script.pay2wsh(Script.createMultiSigMofN(2, keys)), multisigEntries(0, 0))
        // Only a mismatch if the cosigner order does not happen to be sorted already.
        if (keys != keys.sortedBy { it.value.toHex() }) assertTrue(unsorted.verifyOutput(0, multisig) is OutputOwnership.Mismatch)
        assertEquals(OutputOwnership.Ours(0, 0), unsorted.verifyOutput(0, multisig.copy(sortedKeys = false)))
    }

    @Test
    fun multisigOutputWithoutAnyCosignerEntryIsExternal() {
        val psbt = output(Script.pay2wsh(sortedMulti(cosignerKeys(0, 0))))
        assertEquals(OutputOwnership.External, psbt.verifyOutput(0, multisig))
    }
}
