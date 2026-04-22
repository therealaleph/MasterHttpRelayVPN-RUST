# Keep our JNI entry points so R8 doesn't strip them in release builds.
# These methods are declared `external` in Kotlin — the JNI linker looks
# them up by exact name at load time.
-keep class com.therealaleph.mhrv.Native { *; }
-keep class com.therealaleph.mhrv.MhrvVpnService { *; }
