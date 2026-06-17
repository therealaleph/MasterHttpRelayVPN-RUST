package com.therealaleph.mhrv.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject

class CaRepositoryImpl @Inject constructor(@ApplicationContext private val ctx: Context) :
    CaRepository {

    override suspend fun prepareCaDialogData(): CaCertInfo? {
        return withContext(Dispatchers.IO) {
            val exported = CaInstall.export(ctx)
            if (!exported) return@withContext null
            val fingerprint = CaInstall.fingerprint(ctx) ?: return@withContext null
            val hex = CaInstall.fingerprintHex(fingerprint)
            val subjectCn = CaInstall.subjectCn(ctx)
            return@withContext CaCertInfo(
                fingerprint, hex, subjectCn
            )
        }
    }

    override suspend fun saveToDownloads(): String? {
        return withContext(Dispatchers.IO) {
            return@withContext CaInstall.saveToDownloads(ctx)
        }
    }

    override suspend fun checkInstalled(fingerprint: ByteArray): Boolean {
        return withContext(Dispatchers.IO) {
            return@withContext CaInstall.isInstalled(fingerprint)
        }
    }
}