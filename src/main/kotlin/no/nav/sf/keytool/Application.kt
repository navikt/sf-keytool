package no.nav.sf.keytool

import com.google.gson.Gson
import mu.KotlinLogging
import no.nav.sf.keytool.cert.baseDir
import no.nav.sf.keytool.cert.certHandler
import no.nav.sf.keytool.cert.downloadHandler
import no.nav.sf.keytool.cert.listCerts
import no.nav.sf.keytool.cert.testCertHandler
import no.nav.sf.keytool.db.PostgresDatabase
import no.nav.sf.keytool.token.AuthRouteBuilder
import no.nav.sf.keytool.token.DefaultAccessTokenHandler
import no.nav.sf.keytool.token.DefaultTokenValidator
import no.nav.sf.keytool.token.MockTokenValidator
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.http4k.core.HttpHandler
import org.http4k.core.Method
import org.http4k.core.Response
import org.http4k.core.Status.Companion.OK
import org.http4k.routing.ResourceLoader
import org.http4k.routing.bind
import org.http4k.routing.path
import org.http4k.routing.routes
import org.http4k.routing.static
import org.http4k.server.Http4kServer
import org.http4k.server.Netty
import org.http4k.server.asServer
import java.security.Security
import java.time.Duration
import java.time.Instant

class Application {
    private val log = KotlinLogging.logger { }

    val local: Boolean = System.getenv(env_NAIS_CLUSTER_NAME) == null

    val context = env(config_CONTEXT)

    val tokenValidator = if (local) MockTokenValidator() else DefaultTokenValidator()

    val cluster = if (local) "local" else env(env_NAIS_CLUSTER_NAME)

    val accessTokenHandler =
        DefaultAccessTokenHandler(
            sfTokenHost = env(config_SF_TOKENHOST),
            sfClientId = env(secret_SF_CLIENT_ID),
            sfUsername = env(secret_SF_USERNAME),
            keystoreJksB64 = env(secret_KEYSTORE_JKS_B64),
            keystorePassword = env(secret_KEYSTORE_PASSWORD),
        )

    fun apiServer(port: Int): Http4kServer = api().asServer(Netty(port))

    fun api(): HttpHandler =
        routes(
            "/internal/isAlive" bind Method.GET to { Response(OK) },
            "/internal/isReady" bind Method.GET to { Response(OK) },
            "/internal/metrics" bind Method.GET to Metrics.metricsHttpHandler,
            "/internal/hello" bind Method.GET to { Response(OK).body("Hello") },
            "/internal/secrethello" authbind Method.GET to { Response(OK).body("Secret Hello") },
            "/internal/gui" bind Method.GET to static(ResourceLoader.Classpath("gui")),
            "/internal/access" bind Method.GET to { Response(OK).body("Got access token for instance: ${accessTokenHandler.instanceUrl}") },
            // Generate + store cert under /tmp/sf-certs/{cn}
            "/internal/cert/generate" bind Method.POST to certHandler,
            // List existing certs
            "/internal/cert/list" bind Method.GET to {
                val payload =
                    listCerts().map {
                        mapOf(
                            "cn" to it.cn,
                            "expiresAt" to it.expiresAt.toString(),
                            "daysLeft" to Duration.between(Instant.now(), it.expiresAt).toDays(),
                            "sfClientId" to it.sfClientId,
                            "sfUsername" to it.sfUsername,
                        )
                    }

                Response(OK)
                    .header("Content-Type", "application/json")
                    .body(Gson().toJson(payload))
            },
            // Download files: cer | jks | password
            "/internal/cert/download/{cn}/{file}" bind Method.GET to { req ->
                val cn = req.path("cn")!!
                val file = req.path("file")!!
                downloadHandler(cn, file)
            },
            "/internal/cert/test" bind Method.POST to testCertHandler,
            "/internal/clearDb" bind Method.GET to clearDbHandler,
            "/internal/initDb" bind Method.GET to initDbHandler,
        )

    /**
     * authbind: a variant of bind that takes care of authentication with use of tokenValidator
     */
    infix fun String.authbind(method: Method) = AuthRouteBuilder(this, method, tokenValidator)

    fun installBouncyCastle() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    fun start() {
        installBouncyCastle()
        log.info { "Starting in cluster $cluster" }
        apiServer(8080).start()
    }

    private val clearDbHandler: HttpHandler = {
        PostgresDatabase.createCertMetadataTable(true)
        Response(OK).body("Table recreated")
    }

    private val initDbHandler: HttpHandler = {
        PostgresDatabase.createCertMetadataTable(true)
        Response(OK).body("Table created")
    }
}
