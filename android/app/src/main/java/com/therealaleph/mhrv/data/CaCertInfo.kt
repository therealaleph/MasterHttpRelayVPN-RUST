package com.therealaleph.mhrv.data

data class CaCertInfo(
    val fingerprint: ByteArray,
    val fingerprintHex: String,
    val subjectCn: String?
)
