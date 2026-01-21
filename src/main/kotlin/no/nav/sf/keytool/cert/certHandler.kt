@file:Suppress("ktlint:standard:filename", "ktlint:standard:property-naming")

package no.nav.sf.keytool.cert

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.http4k.core.Body
import org.http4k.core.HttpHandler
import org.http4k.core.Method
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status
import org.http4k.core.body.form
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date

val certHandler: HttpHandler = certHandler@{ req ->

    if (req.method != Method.POST) {
        return@certHandler Response(Status.METHOD_NOT_ALLOWED)
    }

    val cn =
        req.form("cn")
            ?: return@certHandler Response(Status.BAD_REQUEST).body("Missing cn")

    val days = req.form("days")?.toIntOrNull() ?: 1200

    val password =
        req.form("password")
            ?: return@certHandler Response(Status.BAD_REQUEST).body("Missing password")

    val keyPair = generateKeyPair()
    val cert = generateCertificate(cn, keyPair, days)

    val jksBytes = createKeystore(keyPair.private, cert, password)
    val jksB64 = Base64.getEncoder().encodeToString(jksBytes)

    File("/tmp/jks").writeText("jksBytes size: " + jksBytes.size + "\n" + jksB64)
    File("/tmp/cert").writeText(cert.encoded.toString(Charsets.UTF_8))

    Response(Status.OK)
        .header("Content-Type", "application/x-x509-ca-cert")
        .header(
            "Content-Disposition",
            "attachment; filename=\"salesforce-jwt.cer\"",
        ).header("X-KEYSTORE-JKS-B64", jksB64)
        .header("X-KEYSTORE-PASSWORD", password)
        .body(cert.encoded.inputStream())
}

private fun generateKeyPair(): KeyPair =
    KeyPairGenerator
        .getInstance("RSA")
        .apply {
            initialize(4096)
        }.generateKeyPair()

private fun generateCertificate(
    cn: String,
    keyPair: KeyPair,
    days: Int,
): X509Certificate {
    val now = Date()
    val until = Date(now.time + days * 24L * 60 * 60 * 1000)

    val subject = X500Name("CN=$cn")

    val certBuilder =
        JcaX509v3CertificateBuilder(
            subject, // issuer
            BigInteger(64, SecureRandom()), // serial
            now, // notBefore
            until, // notAfter
            subject, // subject
            keyPair.public,
        )

    val signer =
        JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(keyPair.private)

    val certHolder: X509CertificateHolder = certBuilder.build(signer)

    return JcaX509CertificateConverter()
        .setProvider("BC")
        .getCertificate(certHolder)
}

private const val KEY_ALIAS = "jwt"

private fun createKeystore(
    privateKey: PrivateKey,
    cert: X509Certificate,
    password: String,
): ByteArray =
    ByteArrayOutputStream().use { out ->
        KeyStore.getInstance("JKS").apply {
            load(null, null)
            setKeyEntry(
                KEY_ALIAS,
                privateKey,
                password.toCharArray(),
                arrayOf(cert),
            )
            store(out, password.toCharArray())
        }
        out.toByteArray()
    }
