@file:Suppress("unused")

package com.gorunjinian.vaultovich

import com.gorunjinian.vaultovich.crypto.Pbkdf2
import java.text.Normalizer
import kotlin.jvm.JvmStatic

object MnemonicCode {
    val englishWordlist: List<String>
        get() = BIP39_ENGLISH_WORDLIST

    /** BIP-39: ENT is 128..256 bits in 32-bit steps, i.e. 12, 15, 18, 21 or 24 words. */
    @JvmField
    val VALID_WORD_COUNTS: Set<Int> = setOf(12, 15, 18, 21, 24)

    /** BIP-39: entropy is 16..32 bytes in 4-byte steps. */
    @JvmField
    val VALID_ENTROPY_SIZES: Set<Int> = setOf(16, 20, 24, 28, 32)

    private val WHITESPACE = Regex("\\s+")

    /**
     * BIP-39 mandates Unicode NFKD for the mnemonic sentence, the wordlist and the passphrase. Among
     * other things this maps the ideographic space (U+3000) used by the Japanese wordlist to U+0020
     * and decomposes precomposed accented characters, so that every wallet derives the same seed
     * from the same visible text.
     */
    @JvmStatic
    fun normalize(input: String): String = Normalizer.normalize(input, Normalizer.Form.NFKD)

    /** Split a mnemonic sentence into words: NFKD first, then on any run of whitespace. */
    private fun splitSentence(sentence: String): List<String> =
        normalize(sentence).trim().split(WHITESPACE).filter { it.isNotEmpty() }

    private fun toBinary(x: Byte): List<Boolean> {
        tailrec fun loop(x: Int, acc: List<Boolean> = listOf()): List<Boolean> =
            if (x == 0) acc else loop(x / 2, listOf((x % 2) != 0) + acc)

        val digits = loop(x.toInt() and 0xff)
        val zeroes = List(8 - digits.size) { false }
        return zeroes + digits
    }

    private fun toBinary(x: ByteArray): List<Boolean> = x.map(MnemonicCode::toBinary).flatten()

    private fun fromBinary(bin: List<Boolean>): Int = bin.fold(0) { acc, flag -> if (flag) 2 * acc + 1 else 2 * acc }

    private tailrec fun group(items: List<Boolean>, size: Int, acc: List<List<Boolean>> = emptyList()): List<List<Boolean>> {
        return when {
            items.isEmpty() -> acc
            items.size < size -> acc + listOf(items)
            else -> group(items.drop(size), size, acc + listOf(items.take(size)))
        }
    }

    /**
     * @param mnemonics list of mnemonic words
     * @param wordlist optional dictionary of 2048 mnemonic words, default to the English mnemonic words if not specified
     * @throws RuntimeException if the mnemonic words are not valid
     */
    @JvmStatic
    fun validate(mnemonics: List<String>, wordlist: List<String> = englishWordlist) {
        require(wordlist.size == 2048) { "invalid word list (size should be 2048)" }
        require(mnemonics.isNotEmpty()) { "mnemonic code cannot be empty" }
        require(mnemonics.size in VALID_WORD_COUNTS) { "invalid mnemonic word count ${mnemonics.size}, it must be one of $VALID_WORD_COUNTS" }
        val wordMap = wordlist.mapIndexed { index, s -> s to index }.toMap()
        // Report the position, never the word: a mnemonic word is a fragment of the seed.
        mnemonics.forEachIndexed { i, word -> require(wordMap.contains(word)) { "invalid mnemonic word at position ${i + 1}" } }
        val indexes = mnemonics.map { word -> wordMap.getValue(word) }

        tailrec fun toBits(index: Int, acc: List<Boolean> = listOf()): List<Boolean> =
            if (acc.size == 11) acc else toBits(index / 2, listOf(index % 2 != 0) + acc)

        val bits = indexes.map { toBits(it) }.flatten()
        val bitlength = (bits.size * 32) / 33
        val databits = bits.subList(0, bitlength)
        val checksumbits = bits.subList(bitlength, bits.size)
        val data = group(databits, 8).map { fromBinary(it) }.map { it.toByte() }.toByteArray()
        val check = toBinary(Crypto.sha256(data)).take(data.size / 4)
        require(check == checksumbits) { "invalid checksum" }
    }

    @JvmStatic
    fun validate(mnemonics: String): Unit = validate(splitSentence(mnemonics))

    /**
     * BIP39 entropy encoding
     *
     * @param entropy  input entropy
     * @param wordlist word list (must be 2048 words long)
     * @return a list of mnemonic words that encodes the input entropy
     */
    @JvmStatic
    fun toMnemonics(entropy: ByteArray, wordlist: List<String>): List<String> {
        require(wordlist.size == 2048) { "invalid word list (size should be 2048)" }
        require(entropy.size in VALID_ENTROPY_SIZES) { "invalid entropy size ${entropy.size}, it must be one of $VALID_ENTROPY_SIZES bytes" }
        val digits = toBinary(entropy) + toBinary(Crypto.sha256(entropy)).take(entropy.size / 4)

        return group(digits, 11).map(MnemonicCode::fromBinary).map { wordlist[it] }
    }

    @JvmStatic
    fun toMnemonics(entropy: ByteArray): List<String> = toMnemonics(entropy, englishWordlist)

    /**
     * BIP39 seed derivation: PBKDF2-HMAC-SHA512, 2048 rounds, password = the NFKD mnemonic sentence,
     * salt = "mnemonic" + NFKD passphrase, both UTF-8.
     *
     * NB: this does not validate the mnemonic; call [validate] first when the words come from a user.
     *
     * @param mnemonics  mnemonic words
     * @param passphrase passphrase (any Unicode; normalised here)
     * @return a 64-byte seed derived from the mnemonic words and passphrase
     */
    @JvmStatic
    fun toSeed(mnemonics: List<String>, passphrase: String): ByteArray {
        val password = normalize(mnemonics.joinToString(" ")).encodeToByteArray()
        val salt = normalize("mnemonic$passphrase").encodeToByteArray()
        return Pbkdf2.withHmacSha512(password, salt, 2048, 64)
    }

    /** See [toSeed]. The sentence may use any whitespace separator, including U+3000. */
    @JvmStatic
    fun toSeed(mnemonics: String, passphrase: String): ByteArray = toSeed(splitSentence(mnemonics), passphrase)
}