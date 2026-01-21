package no.nav.sf.keytool.token

import com.google.gson.Gson
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import no.nav.sf.keytool.config_SF_TOKENHOST
import no.nav.sf.keytool.env
import no.nav.sf.keytool.secret_KEYSTORE_JKS_B64
import no.nav.sf.keytool.secret_KEYSTORE_PASSWORD
import no.nav.sf.keytool.secret_PRIVATE_KEY_ALIAS
import no.nav.sf.keytool.secret_PRIVATE_KEY_PASSWORD
import no.nav.sf.keytool.secret_SF_CLIENT_ID
import no.nav.sf.keytool.secret_SF_USERNAME
import org.http4k.client.OkHttp
import org.http4k.core.HttpHandler
import org.http4k.core.Method
import org.http4k.core.Request
import org.http4k.core.Response
import org.http4k.core.Status
import org.http4k.core.body.toBody
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.util.Base64

/**
 * A handler for oauth2 access flow to salesforce.
 * @see [sf.remoteaccess_oauth_jwt_flow](https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_jwt_flow.htm&type=5)
 *
 * Fetches and caches access token, also retrieves instance url
 */
class DefaultAccessTokenHandler(
    private val sfTokenHost: String,
    private val sfClientId: String,
    private val sfUsername: String,
    private val keystoreJksB64: String,
    private val keystorePassword: String,
) : AccessTokenHandler {
    override val accessToken get() = fetch().first
    override val instanceUrl get() = fetch().second
    override val tenantId get() = fetch().third

    private val log = KotlinLogging.logger {}
    private val client: HttpHandler = OkHttp()
    private val gson = Gson()

    private val expTimeSecondsClaim = 3600
    private var cached: Triple<String, String, String>? = null
    private var expireAtMillis = 0L

    private fun fetch(): Triple<String, String, String> {
        val now = System.currentTimeMillis()
        if (cached != null && now < expireAtMillis) {
            log.debug { "Using cached Salesforce access token" }
            return cached!!
        }

        val jwt = buildJwtAssertion()
        val request =
            Request(Method.POST, sfTokenHost)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(
                    listOf(
                        "grant_type" to "urn:ietf:params:oauth:grant-type:jwt-bearer",
                        "assertion" to jwt,
                    ).toBody(),
                )

        val response = client(request)
        if (response.status != Status.OK) {
            throw IllegalStateException(
                "Salesforce token request failed: ${response.status}\n${response.bodyString()}",
            )
        }

        val parsed =
            gson.fromJson(response.bodyString(), AccessTokenResponse::class.java)

        val triplet =
            Triple(
                parsed.access_token,
                parsed.instance_url,
                parsed.id.split("/")[4],
            )

        cached = triplet
        expireAtMillis = now + 10 * 60 * 1000 // cache 10 minutes

        return triplet
    }

    private fun buildJwtAssertion(): String {
        val exp =
            (System.currentTimeMillis() / 1000) + expTimeSecondsClaim

        val claim =
            JWTClaim(
                iss = sfClientId,
                aud = sfTokenHost,
                sub = sfUsername,
                exp = exp,
            )

        val headerJson = gson.toJson(JWTHeader("RS256"))
        val claimJson = gson.toJson(claim)

        val unsigned =
            "${headerJson.encodeB64UrlSafe()}.${claimJson.encodeB64UrlSafe()}"

        val privateKey = loadPrivateKey()
        val signature = privateKey.sign(unsigned.toByteArray())

        return "$unsigned.$signature"
    }

    private fun loadPrivateKey(): PrivateKey =
        KeyStore
            .getInstance("JKS")
            .apply {
                load(
                    keystoreJksB64.decodeB64().inputStream(),
                    keystorePassword.toCharArray(),
                )
            }.getKey("jwt", keystorePassword.toCharArray()) as PrivateKey

    private fun PrivateKey.sign(data: ByteArray): String =
        Signature
            .getInstance("SHA256withRSA")
            .apply {
                initSign(this@sign)
                update(data)
            }.sign()
            .encodeB64UrlSafe()

    private fun ByteArray.encodeB64UrlSafe(): String = Base64.getUrlEncoder().withoutPadding().encodeToString(this)

    private fun String.decodeB64(): ByteArray = Base64.getMimeDecoder().decode(this)

    private fun String.encodeB64UrlSafe(): String = toByteArray(Charsets.UTF_8).encodeB64UrlSafe()

    private data class JWTClaim(
        val iss: String,
        val aud: String,
        val sub: String,
        val exp: Long,
    )

    private data class JWTHeader(
        val alg: String,
    )

    private data class AccessTokenResponse(
        val access_token: String,
        val instance_url: String,
        val id: String,
        val token_type: String,
        val scope: String,
    )
}
