package com.therealaleph.mhrv.di

import com.therealaleph.mhrv.data.CaRepository
import com.therealaleph.mhrv.data.CaRepositoryImpl
import com.therealaleph.mhrv.data.ConfigRepository
import com.therealaleph.mhrv.data.ConfigRepositoryImpl
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
abstract class AppModule {

    @Binds
    @Singleton
    abstract fun bindConfigRepository(
        configRepositoryImpl: ConfigRepositoryImpl
    ): ConfigRepository

    @Binds
    @Singleton
    abstract fun bindCaRepository(
        caRepositoryImpl: CaRepositoryImpl
    ): CaRepository

}