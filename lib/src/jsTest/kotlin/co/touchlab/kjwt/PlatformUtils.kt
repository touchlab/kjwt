package co.touchlab.kjwt

// Returns true when running inside a browser (window is defined), false in Node.js.
@Suppress("UNCHECKED_CAST_TO_EXTERNAL_INTERFACE")
actual fun isWebBrowserPlatform(): Boolean = js("typeof window !== 'undefined'").unsafeCast<Boolean>()