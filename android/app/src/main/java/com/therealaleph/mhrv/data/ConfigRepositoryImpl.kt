package com.therealaleph.mhrv.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import javax.inject.Inject

class ConfigRepositoryImpl @Inject constructor(@ApplicationContext private val ctx: Context) :
    ConfigRepository {

    private val _config = MutableStateFlow(MhrvConfig())

    override val config: StateFlow<MhrvConfig> = _config

    override suspend fun saveConfig(cfg: MhrvConfig) {
        _config.value = cfg
        ConfigStore.save(ctx, cfg)
    }

    override suspend fun loadConfig(): MhrvConfig {
        _config.value = ConfigStore.load(ctx)
        return _config.value
    }

    override fun encodeConfig(cfg: MhrvConfig): String {
        return ConfigStore.encode(cfg)
    }

    override fun decodeConfig(string: String): MhrvConfig? {
        return ConfigStore.decode(string)
    }

}