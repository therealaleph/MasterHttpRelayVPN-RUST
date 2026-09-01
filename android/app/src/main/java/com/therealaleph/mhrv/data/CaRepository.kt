package com.therealaleph.mhrv.data

interface CaRepository {
    suspend fun prepareCaDialogData(): CaCertInfo?
    suspend fun saveToDownloads(): String?
    suspend fun checkInstalled(fingerprint: ByteArray): Boolean
}