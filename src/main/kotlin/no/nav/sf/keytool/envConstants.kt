@file:Suppress("ktlint:standard:filename", "ktlint:standard:property-naming")

package no.nav.sf.keytool

const val env_AZURE_APP_WELL_KNOWN_URL = "AZURE_APP_WELL_KNOWN_URL"
const val env_AZURE_APP_CLIENT_ID = "AZURE_APP_CLIENT_ID"
const val env_AZURE_APP_CLIENT_SECRET = "AZURE_APP_CLIENT_SECRET"
const val env_AZURE_OPENID_CONFIG_TOKEN_ENDPOINT = "AZURE_OPENID_CONFIG_TOKEN_ENDPOINT"

const val env_NAIS_CLUSTER_NAME = "NAIS_CLUSTER_NAME"

const val config_SF_TOKENHOST = "SF_TOKENHOST"

const val secret_SF_CLIENT_ID = "SF_CLIENT_ID"
const val secret_SF_USERNAME = "SF_USERNAME"

const val secret_KEYSTORE_JKS_B64 = "KEYSTORE_JKS_B64"
const val secret_KEYSTORE_PASSWORD = "KEYSTORE_PASSWORD"
const val secret_PRIVATE_KEY_ALIAS = "PRIVATE_KEY_ALIAS"
const val secret_PRIVATE_KEY_PASSWORD = "PRIVATE_KEY_PASSWORD"

/**
 * Shortcut for fetching environment variables
 */
fun env(name: String): String = System.getenv(name) ?: throw NullPointerException("Missing env $name")
