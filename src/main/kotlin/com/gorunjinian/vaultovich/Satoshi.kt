package com.gorunjinian.vaultovich

data class Satoshi(val sat: Long) : Comparable<Satoshi> {
    // @formatter:off
    // Exact arithmetic: amounts come from untrusted PSBTs, and a silent wrap would corrupt the fee shown to the user.
    operator fun plus(other: Satoshi): Satoshi = Satoshi(Math.addExact(sat, other.sat))
    operator fun minus(other: Satoshi): Satoshi = Satoshi(Math.subtractExact(sat, other.sat))
    operator fun times(m: Int): Satoshi = Satoshi(Math.multiplyExact(sat, m.toLong()))
    operator fun times(m: Long): Satoshi = Satoshi(Math.multiplyExact(sat, m))
    operator fun times(m: Double): Satoshi = Satoshi((sat * m).toLong())
    operator fun div(d: Int): Satoshi = Satoshi(sat / d)
    operator fun div(d: Long): Satoshi = Satoshi(sat / d)
    operator fun unaryMinus(): Satoshi = Satoshi(Math.negateExact(sat))
    override fun compareTo(other: Satoshi): Int = sat.compareTo(other.sat)

    fun toLong(): Long = sat

    fun toULong(): ULong = sat.toULong()
    override fun toString(): String = "$sat sat"
    // @formatter:on

    companion object {
        const val COIN: Long = 100_000_000L
        val MAX_MONEY: Satoshi = Satoshi(21_000_000L * COIN)
    }
}

fun Long.toSatoshi(): Satoshi = Satoshi(this)
