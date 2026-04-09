package co.touchlab.kjwt.hardware.helpers

import co.touchlab.kjwt.model.algorithm.Jwa
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryAddValue
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFMutableDictionaryRef
import platform.CoreFoundation.CFStringCreateWithCString
import platform.CoreFoundation.CFStringRef
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFAllocatorDefault
import platform.CoreFoundation.kCFBooleanFalse
import platform.CoreFoundation.kCFBooleanTrue
import platform.CoreFoundation.kCFStringEncodingUTF8
import platform.CoreFoundation.kCFTypeDictionaryKeyCallBacks
import platform.CoreFoundation.kCFTypeDictionaryValueCallBacks
import platform.Foundation.NSBundle
import platform.Foundation.NSData
import platform.Foundation.create
import platform.Security.SecItemAdd
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecItemUpdate
import platform.Security.SecKeyCopyPublicKey
import platform.Security.SecKeyRef
import platform.Security.errSecDuplicateItem
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleAfterFirstUnlock
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrApplicationTag
import platform.Security.kSecAttrKeyClass
import platform.Security.kSecAttrKeyClassPrivate
import platform.Security.kSecAttrService
import platform.Security.kSecAttrSynchronizable
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecClassKey
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitOne
import platform.Security.kSecReturnData
import platform.Security.kSecReturnRef
import platform.Security.kSecValueData
import platform.posix.memcpy

/**
 * Internal helper for managing iOS/macOS Keychain items.
 *
 * Handles both symmetric keys (stored as generic passwords) and asymmetric keys (stored as
 * private key items).
 */
@OptIn(ExperimentalForeignApi::class)
internal object AppleKeychainManager {
    private val SERVICE_NAME: String by lazy {
        NSBundle.mainBundle.bundleIdentifier ?: "co.touchlab.kjwt"
    }

    /**
     * Returns a library-managed default alias for [algorithm] if [key] is null.
     */
    fun getDefaultKey(key: String?, algorithm: Jwa): String =
        key ?: "__kjwt_default_${algorithm.id}_key__"

    /**
     * Returns whether any key material exists for [keyId].
     */
    fun containsKey(keyId: String): Boolean =
        findPrivateKey(keyId) != null || findSymmetricKeyBytes(keyId) != null

    /**
     * Returns a [SecKeyRef] for the private key stored under [keyId], or `null` if not found.
     */
    fun findPrivateKey(keyId: String): SecKeyRef? {
        return memScoped {
            val query = cfMutableDict(6)
            cfDictAdd(query, kSecClass, kSecClassKey)
            cfDictAdd(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate)
            cfDictAdd(query, kSecAttrApplicationTag, keyId.toCFData())
            cfDictAdd(query, kSecMatchLimit, kSecMatchLimitOne)
            cfDictAdd(query, kSecReturnRef, kCFBooleanTrue)
            cfDictAdd(query, kSecAttrSynchronizable, kCFBooleanFalse)

            val result = alloc<CFTypeRefVar>()
            val status = SecItemCopyMatching(query, result.ptr)
            if (status == errSecSuccess) result.value?.reinterpret() else null
        }
    }

    /**
     * Deletes the private key stored under [keyId].
     */
    fun deletePrivateKey(keyId: String) {
        memScoped {
            val query = cfMutableDict(4)
            cfDictAdd(query, kSecClass, kSecClassKey)
            cfDictAdd(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate)
            cfDictAdd(query, kSecAttrApplicationTag, keyId.toCFData())
            cfDictAdd(query, kSecAttrSynchronizable, kCFBooleanFalse)

            val status = SecItemDelete(query)
            check(status == errSecSuccess || status == errSecItemNotFound) {
                "Failed to delete private key '$keyId': $status"
            }
        }
    }

    /**
     * Returns a [SecKeyRef] for the public key derived from the private key stored under [keyId],
     * or `null` if the private key is not found.
     */
    fun findPublicKey(keyId: String): SecKeyRef? {
        val privateKey = findPrivateKey(keyId) ?: return null
        return SecKeyCopyPublicKey(privateKey)
    }

    /**
     * Returns the raw bytes of the symmetric key stored under [keyId], or `null` if not found.
     */
    fun findSymmetricKeyBytes(keyId: String): ByteArray? {
        return memScoped {
            val query = cfMutableDict(6)
            cfDictAdd(query, kSecClass, kSecClassGenericPassword)
            cfDictAdd(query, kSecAttrAccount, toCFString(keyId))
            cfDictAdd(query, kSecAttrService, toCFString(SERVICE_NAME))
            cfDictAdd(query, kSecMatchLimit, kSecMatchLimitOne)
            cfDictAdd(query, kSecReturnData, kCFBooleanTrue)
            cfDictAdd(query, kSecAttrSynchronizable, kCFBooleanFalse)

            val result = alloc<CFTypeRefVar>()
            val status = SecItemCopyMatching(query, result.ptr)

            if (status == errSecSuccess) {
                @Suppress("UNCHECKED_CAST")
                val dataRef = result.value as? CFDataRef
                dataRef?.toByteArray()
            } else {
                null
            }
        }
    }

    /**
     * Stores [keyBytes] as a generic password item under [keyId].
     * Updates the value if an item with the same [keyId] already exists.
     */
    fun storeSymmetricKeyBytes(keyId: String, keyBytes: ByteArray) {
        memScoped {
            val item = cfMutableDict(6)
            cfDictAdd(item, kSecClass, kSecClassGenericPassword)
            cfDictAdd(item, kSecAttrAccount, toCFString(keyId))
            cfDictAdd(item, kSecAttrService, toCFString(SERVICE_NAME))
            // Use kSecAttrAccessibleAfterFirstUnlock which is more broadly available in test environments
            cfDictAdd(item, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlock)
            cfDictAdd(item, kSecAttrSynchronizable, kCFBooleanFalse)
            cfDictAdd(item, kSecValueData, keyBytes.toCFData())

            val addStatus = SecItemAdd(item, null)
            if (addStatus == errSecDuplicateItem) {
                val query = cfMutableDict(4)
                cfDictAdd(query, kSecClass, kSecClassGenericPassword)
                cfDictAdd(query, kSecAttrAccount, toCFString(keyId))
                cfDictAdd(query, kSecAttrService, toCFString(SERVICE_NAME))
                cfDictAdd(query, kSecAttrSynchronizable, kCFBooleanFalse)

                val update = cfMutableDict(1)
                cfDictAdd(update, kSecValueData, keyBytes.toCFData())

                val updateStatus = SecItemUpdate(query, update)
                check(updateStatus == errSecSuccess) {
                    "Failed to update symmetric key '$keyId': $updateStatus"
                }
            } else {
                check(addStatus == errSecSuccess) {
                    "Failed to store symmetric key '$keyId': $addStatus"
                }
            }
        }
    }

    /**
     * Deletes the symmetric key stored under [keyId].
     */
    fun deleteSymmetricKeyBytes(keyId: String) {
        memScoped {
            val query = cfMutableDict(4)
            cfDictAdd(query, kSecClass, kSecClassGenericPassword)
            cfDictAdd(query, kSecAttrAccount, toCFString(keyId))
            cfDictAdd(query, kSecAttrService, toCFString(SERVICE_NAME))
            cfDictAdd(query, kSecAttrSynchronizable, kCFBooleanFalse)

            val status = SecItemDelete(query)
            check(status == errSecSuccess || status == errSecItemNotFound) {
                "Failed to delete symmetric key '$keyId': $status"
            }
        }
    }
}

// ---- CFString helper ----

@OptIn(ExperimentalForeignApi::class)
internal fun toCFString(s: String): CFStringRef =
    CFStringCreateWithCString(null, s, kCFStringEncodingUTF8)
        ?: error("Failed to create CFStringRef for '$s'")

// ---- CFDictionary helpers ----

@OptIn(ExperimentalForeignApi::class)
internal fun cfMutableDict(capacity: Int): CFMutableDictionaryRef =
    CFDictionaryCreateMutable(
        null,
        capacity.toLong(),
        kCFTypeDictionaryKeyCallBacks.ptr,
        kCFTypeDictionaryValueCallBacks.ptr,
    )!!

@OptIn(ExperimentalForeignApi::class)
internal fun cfDictAdd(dict: CFMutableDictionaryRef, key: CFTypeRef?, value: CFTypeRef?) {
    CFDictionaryAddValue(dict, key, value)
}

// ---- ByteArray <-> CFDataRef helpers ----

@OptIn(ExperimentalForeignApi::class)
internal fun ByteArray.toCFData(): CFDataRef =
    usePinned { pinned ->
        CFDataCreate(
            kCFAllocatorDefault,
            pinned.addressOf(0).reinterpret(),
            this.size.toLong()
        )
    } ?: error("Failed to allocate CFDataRef from ByteArray")

@OptIn(ExperimentalForeignApi::class)
internal fun String.toCFData(): CFDataRef = encodeToByteArray().toCFData()

@OptIn(ExperimentalForeignApi::class)
internal fun CFDataRef.toByteArray(): ByteArray {
    val length = CFDataGetLength(this).toInt()
    if (length == 0) return ByteArray(0)
    val ptr = CFDataGetBytePtr(this) ?: return ByteArray(0)

    val byteArray = ByteArray(length)
    byteArray.usePinned { pinned ->
        memcpy(pinned.addressOf(0), ptr, length.toULong())
    }
    return byteArray
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
internal fun ByteArray.toNSData(): NSData =
    usePinned { pinned ->
        NSData.create(
            bytes = pinned.addressOf(0),
            length = size.toULong(),
        )
    }
