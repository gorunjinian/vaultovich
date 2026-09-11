package com.gorunjinian.vaultovich

import com.gorunjinian.vaultovich.MnemonicCode.toMnemonics
import com.gorunjinian.vaultovich.MnemonicCode.toSeed
import fr.acinq.secp256k1.Hex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

class MnemonicCodeTest {

    @Test
    fun bip39CanonicalAbandonAboutSeed() {
        val mnemonics = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        val seed = MnemonicCode.toSeed(mnemonics, "")
        assertEquals(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1" +
                "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            Hex.encode(seed)
        )
    }

    @Test
    fun bip39SampleVectorWithTrezorPassphrase() {
        // From the canonical BIP-39 vectors (passphrase=TREZOR), single sample.
        val entropy = Hex.decode("00000000000000000000000000000000")
        val expectedMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        val expectedSeedHex = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        val mnemonic = toMnemonics(entropy).joinToString(" ")
        assertEquals(expectedMnemonic, mnemonic)
        val seed = toSeed(mnemonic, "TREZOR")
        assertEquals(expectedSeedHex, Hex.encode(seed))
    }

    @Test
    fun validRoundTripForRandomEntropy() {
        val random = Random
        for (length in listOf(16, 20, 24, 28, 32)) {
            repeat(5) {
                val entropy = ByteArray(length).also { random.nextBytes(it) }
                val mnemonics = toMnemonics(entropy)
                MnemonicCode.validate(mnemonics)
            }
        }
    }

    @Test
    fun invalidMnemonicsAreRejected() {
        val invalidMnemonics = listOf(
            "",
            // One word missing
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow",
            // One extra word
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog fog",
            // Wrong word (still in wordlist, but bad checksum)
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fig"
        )
        for (mnemonic in invalidMnemonics) {
            var threw = false
            try {
                MnemonicCode.validate(mnemonic)
            } catch (_: Throwable) {
                threw = true
            }
            assertTrue("expected '$mnemonic' to fail validation", threw)
        }
    }

    @Test
    fun wordCountMustBeOneOfTheBip39Sizes() {
        // 9 words is a multiple of 3 but not a BIP-39 size (ENT would be 96 bits).
        val nine = List(9) { "abandon" }
        val e = runCatching { MnemonicCode.validate(nine) }.exceptionOrNull()
        assertTrue("expected a word-count failure, got $e", e?.message?.contains("word count") == true)
        // 12 bytes of entropy is likewise not a BIP-39 size.
        assertTrue(runCatching { toMnemonics(ByteArray(12)) }.isFailure)
        assertTrue(runCatching { toMnemonics(ByteArray(16)) }.isSuccess)
    }

    /**
     * Official Japanese vectors (github.com/bip32JP/bip32JP.github.io, test_JP_BIP39.json). The words
     * are separated by U+3000 and the passphrase contains characters (㍍, ゞ, ヴ) whose NFKD form
     * differs from the typed form, so these fail unless both are normalised as BIP-39 requires.
     */
    @Test
    fun bip39JapaneseVectorsRequireNfkd() {
        val passphrase = "㍍ガバヴァぱばぐゞちぢ十人十色"
        val vectors = listOf(
            Pair(
                "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら",
                "a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55",
            ),
            Pair(
                "そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかめ",
                "aee025cbe6ca256862f889e48110a6a382365142f7d16f2b9545285b3af64e542143a577e9c144e101a6bdca18f8d97ec3366ebf5b088b1c1af9bc31346e60d9",
            ),
        )
        for ((sentence, expectedSeed) in vectors) {
            assertEquals(expectedSeed, Hex.encode(toSeed(sentence, passphrase)))
            assertEquals(expectedSeed, Hex.encode(toSeed(sentence.split("　"), passphrase)))
        }
    }

    @Test
    fun passphraseIsNfkdNormalised() {
        val mnemonics = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        val composed = "café"       // e-acute, precomposed
        val decomposed = "café"    // e + combining acute
        assertTrue(toSeed(mnemonics, composed).contentEquals(toSeed(mnemonics, decomposed)))
        // Compatibility characters decompose too: the full-width 'Ａ' is the ASCII 'A' under NFKD.
        assertTrue(toSeed(mnemonics, "Ａ").contentEquals(toSeed(mnemonics, "A")))
    }

    @Test
    fun sentenceWhitespaceIsTolerated() {
        val words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        val seed = toSeed(words, "")
        assertTrue(toSeed("  $words ", "").contentEquals(seed))
        assertTrue(toSeed(words.replace(" ", "　"), "").contentEquals(seed))
        MnemonicCode.validate(words.replace(" ", "  "))
    }
}
