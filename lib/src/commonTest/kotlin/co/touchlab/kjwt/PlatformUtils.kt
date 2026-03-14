package co.touchlab.kjwt

/** Returns true when tests run inside a browser (Chrome/WebKit/etc.) or wasmJs, where
 *  the Web Crypto API does not support 192-bit AES keys. */
expect fun isWebBrowserPlatform(): Boolean