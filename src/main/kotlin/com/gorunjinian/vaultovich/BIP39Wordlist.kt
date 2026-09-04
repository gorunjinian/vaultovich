package com.gorunjinian.vaultovich

/**
 * Utility class for accessing the BIP39 wordlist.
 *
 * The wordlist is compiled into the library as [BIP39_ENGLISH_WORDLIST]; nothing
 * is read from disk or from platform resources.
 */
object BIP39Wordlist {

    /**
     * Gets the English BIP39 wordlist.
     *
     * @return List of 2048 BIP39 English words
     */
    fun getEnglishWordlist(): List<String> = BIP39_ENGLISH_WORDLIST

    /**
     * Gets words that match a given prefix (useful for autocomplete).
     *
     * @param prefix Word prefix to match
     * @return List of matching words
     */
    fun getWordsWithPrefix(prefix: String): List<String> {
        if (prefix.isEmpty()) return emptyList()
        val lowercasePrefix = prefix.lowercase()
        return BIP39_ENGLISH_WORDLIST.filter { it.startsWith(lowercasePrefix) }
    }
}
