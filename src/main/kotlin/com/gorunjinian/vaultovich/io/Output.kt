package com.gorunjinian.vaultovich.io

interface Output {
    fun write(buffer: ByteArray, offset: Int = 0, count: Int = buffer.size)
    fun write(byteValue: Int)
}
