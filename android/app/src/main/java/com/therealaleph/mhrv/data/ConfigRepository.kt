package com.therealaleph.mhrv.data

import android.content.Context
import kotlinx.coroutines.flow.StateFlow

interface ConfigRepository {
    val config: StateFlow<MhrvConfig>
    suspend fun saveConfig(cfg: MhrvConfig)
    suspend fun loadConfig(): MhrvConfig
    fun encodeConfig(cfg: MhrvConfig): String
    fun decodeConfig(string: String): MhrvConfig?
}