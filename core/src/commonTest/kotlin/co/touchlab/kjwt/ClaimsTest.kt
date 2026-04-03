package co.touchlab.kjwt

import co.touchlab.kjwt.ext.audience
import co.touchlab.kjwt.ext.audienceOrNull
import co.touchlab.kjwt.ext.expiration
import co.touchlab.kjwt.ext.expirationOrNull
import co.touchlab.kjwt.ext.getClaim
import co.touchlab.kjwt.ext.getClaimOrNull
import co.touchlab.kjwt.ext.issuedAt
import co.touchlab.kjwt.ext.issuedAtOrNull
import co.touchlab.kjwt.ext.issuer
import co.touchlab.kjwt.ext.issuerOrNull
import co.touchlab.kjwt.ext.jwtId
import co.touchlab.kjwt.ext.jwtIdOrNull
import co.touchlab.kjwt.ext.notBefore
import co.touchlab.kjwt.ext.notBeforeOrNull
import co.touchlab.kjwt.ext.subject
import co.touchlab.kjwt.ext.subjectOrNull
import co.touchlab.kjwt.model.JwtPayload
import io.kotest.core.spec.style.FunSpec
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class ClaimsTest :
    FunSpec({

        fun emptyClaims() = JwtPayload.Builder().build(
            Jwt.defaultJsonParser
        )

        fun claimsWithSubject() =
            JwtPayload
                .Builder()
                .apply {
                    subject = "test-subject"
                }.build(Jwt.defaultJsonParser)

        context("registered claims missing throws NullPointerException") {

            test("issuer missing throws NullPointerException") {
                assertFailsWith<NullPointerException> { emptyClaims().issuer }
            }

            test("subject missing throws NullPointerException") {
                assertFailsWith<NullPointerException> { emptyClaims().subject }
            }

            test("audience missing throws NullPointerException") {
                assertFailsWith<NullPointerException> { emptyClaims().audience }
            }

            test("expiration missing throws NullPointerException") {
                assertFailsWith<NullPointerException> { emptyClaims().expiration }
            }

            test("notBefore missing throws NullPointerException") {
                assertFailsWith<NullPointerException> { emptyClaims().notBefore }
            }

            test("issuedAt missing throws NullPointerException") {
                assertFailsWith<NullPointerException> { emptyClaims().issuedAt }
            }

            test("jwtId missing throws NullPointerException") {
                assertFailsWith<NullPointerException> { emptyClaims().jwtId }
            }
        }

        context("registered claims missing returns null") {

            test("issuerOrNull missing returns null") {
                assertNull(emptyClaims().issuerOrNull)
            }

            test("subjectOrNull missing returns null") {
                assertNull(emptyClaims().subjectOrNull)
            }

            test("audienceOrNull missing returns null") {
                assertNull(emptyClaims().audienceOrNull)
            }

            test("expirationOrNull missing returns null") {
                assertNull(emptyClaims().expirationOrNull)
            }

            test("notBeforeOrNull missing returns null") {
                assertNull(emptyClaims().notBeforeOrNull)
            }

            test("issuedAtOrNull missing returns null") {
                assertNull(emptyClaims().issuedAtOrNull)
            }

            test("jwtIdOrNull missing returns null") {
                assertNull(emptyClaims().jwtIdOrNull)
            }
        }

        context("custom claims") {

            test("getClaim missing throws NullPointerException") {
                assertFailsWith<NullPointerException> { emptyClaims().getClaim<String>("role") }
            }

            test("getClaimOrNull missing returns null") {
                assertNull(emptyClaims().getClaimOrNull<String>("role"))
            }

            test("getClaim present returns value") {
                val claims = claimsWithSubject()
                assertEquals("test-subject", claims.subject)
            }

            test("getClaimOrNull present returns value") {
                val claims = claimsWithSubject()
                assertEquals("test-subject", claims.subjectOrNull)
            }
        }
    })
