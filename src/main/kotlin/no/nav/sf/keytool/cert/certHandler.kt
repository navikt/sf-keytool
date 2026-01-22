@file:Suppress("ktlint:standard:filename", "ktlint:standard:property-naming")

package no.nav.sf.keytool.cert

import no.nav.sf.keytool.config_SF_TOKENHOST
import no.nav.sf.keytool.db.PostgresDatabase
import no.nav.sf.keytool.env
import no.nav.sf.keytool.token.DefaultAccessTokenHandler
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
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64
import java.util.Date

val baseDir = File("/tmp/sf-certs")

data class CertMetadata(
    val cn: String,
    val expiresAt: Instant,
    val sfClientId: String?,
    val sfUsername: String?,
)

fun generateAndStoreCert(
    cn: String,
    days: Int,
    password: String,
): CertMetadata {
    val dir = File(baseDir, cn)
    require(!dir.exists()) { "Certificate with CN=$cn already exists" }
    dir.mkdirs()

    val keyPair = generateKeyPair()
    val cert = generateCertificate(cn, keyPair, days)
    val jksBytes = createKeystore(keyPair.private, cert, password)
    val jksB64 = Base64.getEncoder().encodeToString(jksBytes)

    File(dir, "$cn.cer").writeBytes(cert.encoded)
    File(dir, "$cn.jks").writeBytes(jksBytes)
    File(dir, "$cn.jks.b64").writeText(jksB64)
    File(dir, "password.txt").writeText(password)

    val expiresAt = cert.notAfter.toInstant()
    File(dir, "metadata.json").writeText(
        """
        {
          "cn": "$cn",
          "expiresAt": "$expiresAt"
        }
        """.trimIndent(),
    )

    return CertMetadata(cn, expiresAt, null, null)
}

fun listTmpCerts(): List<CertMetadata> =
    baseDir.listFiles()?.mapNotNull { dir ->
        val meta = File(dir, "metadata.json")
        if (!meta.exists()) return@mapNotNull null

        val expiresAt =
            Regex("\"expiresAt\": \"(.*?)\"")
                .find(meta.readText())!!
                .groupValues[1]

        val sfClientId =
            File(dir, "sf_client_id.txt")
                .takeIf { it.exists() }
                ?.readText()

        val sfUsername =
            File(dir, "sf_username.txt")
                .takeIf { it.exists() }
                ?.readText()

        CertMetadata(
            cn = dir.name,
            expiresAt = Instant.parse(expiresAt),
            sfClientId = sfClientId,
            sfUsername = sfUsername,
        )
    } ?: emptyList()

fun listDbCerts(): List<CertMetadata> = PostgresDatabase.retrieveCertMetadata()

fun listAllCerts(): List<CertMetadata> {
    val tmp = listTmpCerts()
    val db = listDbCerts()

    val tmpByCn = tmp.associateBy { it.cn }

    val merged =
        tmp +
            db
                .filterNot { it.cn in tmpByCn }
    return merged.sortedBy { it.cn }
}

fun downloadHandler(
    cn: String,
    file: String,
): Response {
    val dir = File(baseDir, cn)
    if (!dir.exists()) return Response(Status.NOT_FOUND)

    val target =
        when (file) {
            "cer" -> File(dir, "$cn.cer")
            "jks" -> File(dir, "$cn.jks")
            "jksb64" -> File(dir, "$cn.jks.b64")
            "password" -> File(dir, "password.txt")
            else -> return Response(Status.BAD_REQUEST)
        }

    if (!target.exists()) return Response(Status.NOT_FOUND)

    return Response(Status.OK)
        .header(
            "Content-Disposition",
            "attachment; filename=\"${target.name}\"",
        ).body(target.inputStream())
}

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

//    val keyPair = generateKeyPair()
//    val cert = generateCertificate(cn, keyPair, days)
//
//    val jksBytes = createKeystore(keyPair.private, cert, password)
//    val jksB64 = Base64.getEncoder().encodeToString(jksBytes)
//
//    File("/tmp/jks").writeText("jksBytes size: " + jksBytes.size + "\n" + jksB64)
//    File("/tmp/cert").writeText(cert.encoded.toString(Charsets.UTF_8))

    val meta = generateAndStoreCert(cn, days, password)

    Response(Status.OK)
        .header("Content-Type", "application/json")
        .body(
            """
            {
              "cn": "${meta.cn}",
              "expiresAt": "${meta.expiresAt}"
            }
            """.trimIndent(),
        )
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

val testCertHandler: HttpHandler = testCertHandler@{ req ->
    if (req.method != Method.POST) {
        return@testCertHandler Response(Status.METHOD_NOT_ALLOWED)
    }

    val cn =
        req.form("cn")
            ?: return@testCertHandler Response(Status.BAD_REQUEST)
                .body("Missing cn")

    val clientId =
        req.form("clientId")
            ?: return@testCertHandler Response(Status.BAD_REQUEST)
                .body("Missing clientId")

    val username =
        req.form("username")
            ?: return@testCertHandler Response(Status.BAD_REQUEST)
                .body("Missing username")

    // Debug (optional)
    File("/tmp/entry").writeText("$cn,$clientId,$username")

    val dir = File(baseDir, cn)
    if (!dir.exists()) return@testCertHandler Response(Status.NOT_FOUND)

    val jksB64 = File(dir, "$cn.jks.b64").readText()
    val password = File(dir, "password.txt").readText()
    val cert = readCertificate(dir, cn)
    val expiresAt = cert.notAfter.toInstant()

    val handler =
        DefaultAccessTokenHandler(
            sfTokenHost = env(config_SF_TOKENHOST),
            sfClientId = clientId,
            sfUsername = username,
            keystoreJksB64 = jksB64,
            keystorePassword = password,
        )

    try {
        val token = handler.accessToken
        File(dir, "sf_client_id.txt").writeText(clientId)
        File(dir, "sf_username.txt").writeText(username)
        PostgresDatabase.upsertCertMetadata(
            CertMetadata(
                cn = cn,
                expiresAt = expiresAt,
                sfUsername = username,
                sfClientId = maskClientId(clientId),
            ),
        )
        Response(Status.OK).body("SUCCESS\nInstance: ${handler.instanceUrl}")
    } catch (e: Exception) {
        Response(Status.BAD_REQUEST).body("FAILED\n${e.message}")
    }
}

fun maskClientId(clientId: String): String =
    if (clientId.length <= 10) {
        "***"
    } else {
        "***" + clientId.takeLast(10)
    }

fun readCertificate(
    dir: File,
    cn: String,
): X509Certificate =
    File(dir, "$cn.cer").inputStream().use { input ->
        CertificateFactory
            .getInstance("X.509")
            .generateCertificate(input) as X509Certificate
    }

val deleteCertHandler: HttpHandler = deleteCertHandler@{ req ->
    val cn =
        req.form("cn")
            ?: return@deleteCertHandler Response(Status.BAD_REQUEST).body("Missing cn")

    val source =
        req.form("source")
            ?: return@deleteCertHandler Response(Status.BAD_REQUEST).body("Missing source")

    val dir = File(baseDir, cn)
    if (dir.exists()) {
        dir.deleteRecursively()
    }

    if (source == "DB") {
        PostgresDatabase.deleteCertMetadata(cn)
    }

    Response(Status.OK).body("Deleted $cn")
}

val flushLocalHandler: HttpHandler = {
    baseDir.listFiles()?.forEach {
        it.deleteRecursively()
    }
    Response(Status.OK).body("Local cert cache flushed")
}
