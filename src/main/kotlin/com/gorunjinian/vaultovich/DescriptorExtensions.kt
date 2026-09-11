package com.gorunjinian.vaultovich

/**
 * Output descriptor generation (BIP-380 to BIP-389) in the multipath form Sparrow, Bitcoin Core
 * and most coordinators accept. Keys are always re-encoded as `xpub` / `tpub`, since those are the
 * only forms descriptors define; SLIP-132 prefixes are accepted as input and normalised.
 */
object DescriptorExtensions {

    /** One cosigner of a multisig wallet, as exchanged between coordinators. */
    data class CosignerKey(
        /** Master key fingerprint of the cosigner. */
        val fingerprint: Long,
        /** Path from the cosigner's master key to [extendedKey], e.g. `m/48'/0'/0'/2'`. */
        val derivationPath: String,
        /** The cosigner's account-level public key in any xpub / SLIP-132 encoding. */
        val extendedKey: String,
    )

    // ==================== Private Helpers ====================

    /**
     * Converts derivation path notation for descriptor format.
     * Removes "m/" prefix and replaces ' with h.
     * @param path Derivation path like "m/84'/0'/0'"
     * @return Formatted path like "84h/0h/0h"
     */
    private fun formatPathForDescriptor(path: String): String =
        path.removePrefix("m/").removePrefix("m").removePrefix("/").replace("'", "h")

    /** `[fingerprint/path]xpub`, the KEY expression of BIP-380 with key origin. */
    private fun keyExpression(fingerprint: Long, path: String, extendedKey: String): String =
        "[${Descriptor.formatFingerprint(fingerprint)}/${formatPathForDescriptor(path)}]${Descriptor.normalizeExtendedPublicKey(extendedKey)}"

    private fun withChecksum(desc: String): String = "$desc#${Descriptor.checksum(desc)}"

    // ==================== Public API ====================

    /**
     * Generates a unified output descriptor with multipath syntax.
     *
     * @param fingerprint Master fingerprint (4 bytes as Long)
     * @param accountPath Account derivation path (e.g., "m/84'/0'/0'")
     * @param extendedKey Account public key in any xpub / SLIP-132 encoding (re-encoded as xpub/tpub)
     * @param scriptType Script type for the wallet
     * @return Descriptor string with checksum
     */
    fun getUnifiedDescriptor(
        fingerprint: Long,
        accountPath: String,
        extendedKey: String,
        scriptType: ScriptType
    ): String {
        val key = keyExpression(fingerprint, accountPath, extendedKey)

        // Build descriptor based on script type
        val desc = when (scriptType) {
            ScriptType.P2WPKH -> "wpkh($key/<0;1>/*)"
            ScriptType.P2TR -> "tr($key/<0;1>/*)"
            ScriptType.P2SH_P2WPKH -> "sh(wpkh($key/<0;1>/*))"
            ScriptType.P2PKH -> "pkh($key/<0;1>/*)"
        }

        return withChecksum(desc)
    }

    /**
     * The key expression this device contributes to a multisig wallet: `[fp/48h/c'h/0h/2h]xpub`.
     *
     * This is what cosigners exchange during setup. It is not a descriptor by itself (BIP-382's
     * `wsh()` must wrap a script expression such as `sortedmulti`, never a bare key); the wallet
     * descriptor is built from every cosigner's key expression with [getBip48Descriptor].
     *
     * @param fingerprint Master fingerprint (4 bytes as Long)
     * @param bip48Path BIP-48 derivation path (e.g., "m/48'/0'/0'/2'")
     * @param extendedKey Account public key in any xpub / SLIP-132 encoding
     */
    fun getBip48KeyExpression(fingerprint: Long, bip48Path: String, extendedKey: String): String =
        keyExpression(fingerprint, bip48Path, extendedKey)

    /**
     * Generates the multisig wallet descriptor for a set of BIP-48 cosigners: `wsh(sortedmulti(k, ...))`
     * or, for P2SH-P2WSH, `sh(wsh(sortedmulti(k, ...)))`, where each key is the cosigner's key
     * expression followed by the multipath `<0;1>` branch and the wildcard child. With checksum.
     *
     * @param threshold Number of required signatures (k of n)
     * @param cosigners Every cosigner, including this device, in the order agreed at setup
     * @param isWrapped True for P2SH-P2WSH (BIP-48 script type 1'), false for P2WSH (script type 2')
     * @param sortedKeys True for `sortedmulti` (BIP-67, order-independent, the norm), false for `multi`
     */
    fun getBip48Descriptor(
        threshold: Int,
        cosigners: List<CosignerKey>,
        isWrapped: Boolean = false,
        sortedKeys: Boolean = true,
    ): String {
        require(cosigners.size in 1..20) { "a multisig descriptor takes 1 to 20 cosigners" }
        require(threshold in 1..cosigners.size) { "threshold must be between 1 and the number of cosigners" }
        val keys = cosigners.joinToString(",") { "${keyExpression(it.fingerprint, it.derivationPath, it.extendedKey)}/<0;1>/*" }
        val script = "${if (sortedKeys) "sortedmulti" else "multi"}($threshold,$keys)"
        val desc = if (isWrapped) "sh(wsh($script))" else "wsh($script)"
        return withChecksum(desc)
    }
}
