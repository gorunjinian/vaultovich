package com.gorunjinian.vaultovich

import com.gorunjinian.vaultovich.DeterministicWallet.derivePrivateKey
import com.gorunjinian.vaultovich.DeterministicWallet.publicKey
import kotlin.jvm.JvmStatic

object Descriptor {
    private fun polyMod(cc: Long, value: Int): Long {
        var c = cc
        val c0 = c shr 35
        c = ((c and 0x7ffffffffL) shl 5) xor value.toLong()
        if ((c0 and 1L) != 0L) c = c xor 0xf5dee51989L
        if ((c0 and 2L) != 0L) c = c xor 0xa9fdca3312L
        if ((c0 and 4L) != 0L) c = c xor 0x1bab10e32dL
        if ((c0 and 8L) != 0L) c = c xor 0x3706b1677aL
        if ((c0 and 16L) != 0L) c = c xor 0x644d626ffdL
        return c
    }

    @JvmStatic
    fun checksum(span: String): String {
        /** A character set designed such that:
         *  - The most common 'unprotected' descriptor characters (hex, keypaths) are in the first group of 32.
         *  - Case errors cause an offset that's a multiple of 32.
         *  - As many alphabetic characters are in the same group (while following the above restrictions).
         *
         * If p(x) gives the position of a character c in this character set, every group of 3 characters
         * (a,b,c) is encoded as the 4 symbols (p(a) & 31, p(b) & 31, p(c) & 31, (p(a) / 32) + 3 * (p(b) / 32) + 9 * (p(c) / 32).
         * This means that changes that only affect the lower 5 bits of the position, or only the higher 2 bits, will just
         * affect a single symbol.
         *
         * As a result, within-group-of-32 errors count as 1 symbol, as do cross-group errors that don't affect
         * the position within the groups.
         */
        val INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}" + "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" + "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "

        /** The character set for the checksum itself (same as bech32). */
        val CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

        var c = 1L
        var cls = 0
        var clscount = 0
        span.forEachIndexed { i, ch ->
            val pos = INPUT_CHARSET.indexOf(ch)
            // Fail loudly: returning "" here used to let callers emit "desc#" with an empty checksum,
            // which the importing wallet rejects without saying why. The character itself is not
            // echoed because the descriptor may contain a private key.
            require(pos != -1) { "descriptor contains an invalid character at position $i" }
            c = polyMod(c, pos and 31) // Emit a symbol for the position inside the group, for every character.
            cls = cls * 3 + (pos shr 5) // Accumulate the group numbers
            clscount += 1
            if (clscount == 3) {
                // Emit an extra symbol representing the group numbers, for every 3 characters.
                c = polyMod(c, cls)
                cls = 0
                clscount = 0
            }
        }
        if (clscount > 0) c = polyMod(c, cls)
        for (j in 0 until 8) c = polyMod(c, 0) // Shift further to determine the checksum.
        c = c xor 1 // Prevent appending zeroes from not affecting the checksum.

        val ret = StringBuilder("        ")
        for (j in 0 until 8) {
            val pos1 = (c shr (5 * (7 - j))) and 31
            val char = CHECKSUM_CHARSET[pos1.toInt()]
            ret[j] = char
        }
        return ret.toString()
    }

    /** BIP-380: the key origin fingerprint is exactly 8 lowercase hex characters. */
    @JvmStatic
    fun formatFingerprint(fingerprint: Long): String = (fingerprint and 0xFFFFFFFFL).toString(16).padStart(8, '0')

    /**
     * Re-encode an extended public key as the `xpub` / `tpub` form descriptors require (BIP-380
     * only defines those two). Accepts every SLIP-132 variant (`ypub`, `zpub`, `Ypub`, `Zpub` and
     * the testnet `u`/`v`/`U`/`V` forms), which is what coordinators hand out; the network is taken
     * from the prefix. Private keys are refused: a signing device never exports them.
     */
    @JvmStatic
    fun normalizeExtendedPublicKey(extendedKey: String): String {
        val prefix = runCatching { Base58Check.decodeWithIntPrefix(extendedKey).first }
            .getOrElse { throw IllegalArgumentException("not a valid extended key") }
        require(prefix !in DeterministicWallet.privatePrefixes) { "private extended keys must not be used in descriptors" }
        val target = when (prefix) {
            in DeterministicWallet.mainnetPublicPrefixes -> DeterministicWallet.xpub
            in DeterministicWallet.testnetPublicPrefixes -> DeterministicWallet.tpub
            else -> throw IllegalArgumentException("unknown extended key prefix")
        }
        val (_, key) = DeterministicWallet.ExtendedPublicKey.decode(extendedKey)
        return DeterministicWallet.encode(key, target)
    }

    /** BIP-84 account path and the xpub prefix for the chain. */
    private fun getBIP84Account(chainHash: BlockHash): Pair<String, Int> = when (chainHash) {
        Block.Testnet4GenesisBlock.hash, Block.Testnet3GenesisBlock.hash, Block.RegtestGenesisBlock.hash, Block.SignetGenesisBlock.hash -> "84'/1'/0'" to DeterministicWallet.tpub
        Block.LivenetGenesisBlock.hash -> "84'/0'/0'" to DeterministicWallet.xpub
        else -> error("invalid chain hash $chainHash")
    }

    /**
     * The BIP-84 receive and change descriptors for the first account of [master]: `wpkh()` of the
     * key origin `[fp/84'/c'/0']`, the account xpub, and the `/0/` (receive) or `/1/` (change) branch
     * followed by the wildcard child, both with checksums.
     */
    @Suppress("FunctionName")
    @JvmStatic
    fun BIP84Descriptors(chainHash: BlockHash, master: DeterministicWallet.ExtendedPrivateKey): Pair<String, String> {
        val (accountPath, _) = getBIP84Account(chainHash)
        val accountPub = publicKey(derivePrivateKey(master, KeyPath(accountPath)))
        return BIP84Descriptors(chainHash, DeterministicWallet.fingerprint(master), accountPub)
    }

    /**
     * @param fingerprint master key fingerprint.
     * @param accountPub the *account-level* public key, i.e. the key at `m/84'/c'/0'`. (Earlier
     * versions derived one level deeper, which described addresses no BIP-84 wallet generates.)
     */
    @Suppress("FunctionName")
    @JvmStatic
    fun BIP84Descriptors(chainHash: BlockHash, fingerprint: Long, accountPub: DeterministicWallet.ExtendedPublicKey): Pair<String, String> {
        val (accountPath, prefix) = getBIP84Account(chainHash)
        val key = "[${formatFingerprint(fingerprint)}/$accountPath]${DeterministicWallet.encode(accountPub, prefix)}"
        val accountDesc = "wpkh($key/0/*)"
        val changeDesc = "wpkh($key/1/*)"
        return Pair(
            "$accountDesc#${checksum(accountDesc)}",
            "$changeDesc#${checksum(changeDesc)}"
        )
    }
}