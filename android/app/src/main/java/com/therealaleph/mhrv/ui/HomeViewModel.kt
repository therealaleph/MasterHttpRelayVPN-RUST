package com.therealaleph.mhrv.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.therealaleph.mhrv.data.CaCertInfo
import com.therealaleph.mhrv.data.CaRepository
import com.therealaleph.mhrv.data.ConfigRepository
import com.therealaleph.mhrv.data.MhrvConfig
import com.therealaleph.mhrv.data.NetworkDetect
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

@HiltViewModel
class HomeViewModel @Inject constructor(
    private val configRepository: ConfigRepository,
    private val caRepository: CaRepository
) : ViewModel() {

    val config: StateFlow<MhrvConfig> = configRepository.config

    private val _caCertState = MutableStateFlow<CaCertState>(CaCertState.Idle)
    val caCertState = _caCertState.asStateFlow()

    private val _googleIpResult = MutableSharedFlow<GoogleIpResult>()
    val googleIpResult = _googleIpResult.asSharedFlow()

    init {
        load()
    }

    fun load() {
        viewModelScope.launch {
            configRepository.loadConfig()
        }
    }

    fun saveConfig(cfg: MhrvConfig) {
        viewModelScope.launch {
            configRepository.saveConfig(cfg)
        }
    }

    fun autoDetectGoogleIp() {

        viewModelScope.launch {
            var updated = config.value

            val fresh = withContext(Dispatchers.IO) {
                NetworkDetect.resolveGoogleIp()
            }
            if (!fresh.isNullOrBlank()) {
                updated = updated.copy(googleIp = fresh)
            }
            if (updated.frontDomain.isBlank() ||
                updated.frontDomain.parseAsIpOrNull() != null
            ) {
                updated = updated.copy(frontDomain = "www.google.com")
            }

            if (fresh.isNullOrBlank()) {
                _googleIpResult.emit(GoogleIpResult.Error)
                return@launch
            }

            if (updated != config.value) {
                configRepository.saveConfig(updated)
                _googleIpResult.emit(GoogleIpResult.Success(fresh))
            } else {
                _googleIpResult.emit(GoogleIpResult.NoChange)
            }

        }
    }

    suspend fun prepareConfigForStart() {
        var updated = config.value
        if (config.value.googleIp.isBlank()) {
            val fresh = withContext(Dispatchers.IO) {
                NetworkDetect.resolveGoogleIp()
            }
            if (!fresh.isNullOrBlank()) {
                updated = updated.copy(googleIp = fresh)
            }

        }

        if (updated.frontDomain.isBlank() ||
            updated.frontDomain.parseAsIpOrNull() != null
        ) {
            updated = updated.copy(frontDomain = "www.google.com")
        }

        if (updated != config.value) {
            configRepository.saveConfig(updated)
        }

    }

    fun prepareCaDialogData() {
        viewModelScope.launch {
            _caCertState.value = CaCertState.Loading
            val data = caRepository.prepareCaDialogData()
            if (data != null) {
                _caCertState.value = CaCertState.Ready(data)
            } else {
                _caCertState.value = CaCertState.NotFound
            }
        }
    }

    suspend fun saveToDownloads(): String? {
        return caRepository.saveToDownloads()
    }

    suspend fun checkCaInstall(fingerprint: ByteArray): Boolean {
        return caRepository.checkInstalled(fingerprint)
    }

}

private fun String.parseAsIpOrNull(): java.net.InetAddress? {
    val s = trim()
    if (s.isEmpty() || s.any { it.isLetter() }) return null
    return try {
        // Literal-only parse: rejects anything that would need DNS.
        java.net.InetAddress.getByName(s).takeIf {
            it.hostAddress?.let { addr -> addr == s || addr.contains(s) } == true
        }
    } catch (_: Throwable) {
        null
    }
}

sealed class GoogleIpResult {
    data class Success(val googleIp: String) : GoogleIpResult()
    object Error : GoogleIpResult()
    object NoChange : GoogleIpResult()
}

sealed class CaCertState {
    data class Ready(val info: CaCertInfo) : CaCertState()
    object Idle : CaCertState()
    object Loading : CaCertState()
    object NotFound : CaCertState()
}