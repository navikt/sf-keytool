package no.nav.sf.keytool

import mu.KotlinLogging
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
import org.http4k.routing.routes
import org.http4k.routing.static
import org.http4k.server.Http4kServer
import org.http4k.server.Netty
import org.http4k.server.asServer
import java.security.Security

class Application {
    private val log = KotlinLogging.logger { }

    val local: Boolean = System.getenv(env_NAIS_CLUSTER_NAME) == null

    val tokenValidator = if (local) MockTokenValidator() else DefaultTokenValidator()

    val cluster = if (local) "local" else env(env_NAIS_CLUSTER_NAME)

    val accessTokenHandler = DefaultAccessTokenHandler()

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
            "/internal/cert" bind Method.POST to certHandler,
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

    val certHandler: HttpHandler = {
        Response(OK).body("Cert results")
    }
}
