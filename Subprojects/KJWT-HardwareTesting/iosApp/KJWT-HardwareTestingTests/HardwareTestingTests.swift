import XCTest
import Shared

final class HardwareTestingTests: XCTestCase {
    
    func testES256SignVerify() async throws {
        let processor = try HardwareTesting.shared.getSecureSigningKey(
            keyId: "test-es256",
            algorithm: HardwareTesting.shared.ES256,
            keySizeInBits: 2048,
            secureHardwarePreference: .preferred
        )
        
        let dataStr = "test-data"
        let data = dataStr.data(using: .utf8)!
        let kotlinData = HardwareTesting.shared.toKotlinByteArray(data: data)
        
        let signature = try await processor.sign(data: kotlinData)
        let isValid = try await processor.verify(data: kotlinData, signature: signature)
        
        XCTAssertTrue(isValid.boolValue, "Signature verification should pass")
    }

    func testRS256SignVerify() async throws {
        let processor = try HardwareTesting.shared.getSecureSigningKey(
            keyId: "test-rs256",
            algorithm: HardwareTesting.shared.RS256,
            keySizeInBits: 2048,
            secureHardwarePreference: .none
        )
        
        let dataStr = "test-data-rsa"
        let data = dataStr.data(using: .utf8)!
        let kotlinData = try HardwareTesting.shared.toKotlinByteArray(data: data)
        
        let signature = try await processor.sign(data: kotlinData)
        let isValid = try await processor.verify(data: kotlinData, signature: signature)
        
        XCTAssertTrue(isValid.boolValue, "RSA Signature verification should pass")
    }
    
    func testHS256SignVerify() async throws {
        let processor = try HardwareTesting.shared.getSecureSigningKey(
            keyId: "test-hs256",
            algorithm: HardwareTesting.shared.HS256,
            keySizeInBits: 2048,
            secureHardwarePreference: .none
        )

        let dataStr = "test-data-hmac"
        let data = dataStr.data(using: .utf8)!
        let kotlinData = HardwareTesting.shared.toKotlinByteArray(data: data)

        let signature = try await processor.sign(data: kotlinData)
        let isValid = try await processor.verify(data: kotlinData, signature: signature)

        XCTAssertTrue(isValid.boolValue, "HMAC Signature verification should pass")
    }

    // Preferred falls back to standard Keychain on simulator, uses SE on real device.
    func testES256SecureEnclavePreferred() async throws {
        let processor = try HardwareTesting.shared.getSecureSigningKey(
            keyId: "test-es256-se-preferred",
            algorithm: HardwareTesting.shared.ES256,
            keySizeInBits: 2048,
            secureHardwarePreference: .preferred
        )

        let data = "se-preferred-test".data(using: .utf8)!
        let kotlinData = HardwareTesting.shared.toKotlinByteArray(data: data)
        let signature = try await processor.sign(data: kotlinData)
        let isValid = try await processor.verify(data: kotlinData, signature: signature)

        XCTAssertTrue(isValid.boolValue, "ES256 Preferred: sign/verify should succeed")
    }

    // None preference with ES256 — must use standard hardware-bound Keychain.
    func testES256SecureEnclaveNone() async throws {
        let processor = try HardwareTesting.shared.getSecureSigningKey(
            keyId: "test-es256-se-none",
            algorithm: HardwareTesting.shared.ES256,
            keySizeInBits: 2048,
            secureHardwarePreference: .none
        )

        let data = "se-none-test".data(using: .utf8)!
        let kotlinData = HardwareTesting.shared.toKotlinByteArray(data: data)
        let signature = try await processor.sign(data: kotlinData)
        let isValid = try await processor.verify(data: kotlinData, signature: signature)

        XCTAssertTrue(isValid.boolValue, "ES256 None: sign/verify should succeed")
    }

    // Required with a non-ES256 algorithm must throw immediately (Secure Enclave only supports ES256).
    func testRequiredWithNonES256Throws() {
        XCTAssertThrowsError(
            try HardwareTesting.shared.getSecureSigningKey(
                keyId: "test-rs256-se-required",
                algorithm: HardwareTesting.shared.RS256,
                keySizeInBits: 2048,
                secureHardwarePreference: .required
            )
        ) { error in
            // Expected: IllegalArgumentException propagated from Kotlin
            _ = error
        }
    }
}
