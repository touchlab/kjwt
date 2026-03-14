package co.touchlab.kjwt

// All wasmJs targets (browser and node) use Web Crypto, which does not support 192-bit AES keys.
actual fun isWebBrowserPlatform(): Boolean = true