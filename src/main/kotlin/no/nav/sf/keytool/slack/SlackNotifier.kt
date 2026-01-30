package no.nav.sf.keytool.slack

import com.google.gson.Gson
import no.nav.sf.keytool.cert.registryUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

object SlackNotifier {
    private val gson = Gson()
    private val client = OkHttpClient()

    private val jsonType = "application/json; charset=utf-8".toMediaType()

    fun postMessage(
        webhookUrl: String,
        title: String,
        lines: List<String>,
    ) {
        val payload =
            mapOf(
                "text" to title, // fallback
                "blocks" to buildBlocks(title, lines),
            )

        val body = gson.toJson(payload).toRequestBody(jsonType)

        val request =
            Request
                .Builder()
                .url(webhookUrl)
                .post(body)
                .build()

        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw RuntimeException(
                    "Failed to post Slack message: ${response.code} ${response.message}",
                )
            }
        }
    }

    private fun buildBlocks(
        title: String,
        lines: List<String>,
    ): List<Map<String, Any>> {
        val blocks = mutableListOf<Map<String, Any>>()

        blocks += header(title)
        blocks += divider()

        if (lines.isEmpty()) {
            blocks += section("✅ No certificates expiring soon")
        } else {
            lines.forEach { line ->
                blocks += section("• $line")
            }
        }

        blocks += divider()

        val url = registryUrl()
        blocks +=
            section(
                "Please review the certificate registry *<$url|here>*",
            )

        return blocks
    }

    private fun header(text: String) =
        mapOf(
            "type" to "header",
            "text" to mapOf("type" to "plain_text", "text" to text),
        )

    private fun divider() = mapOf("type" to "divider")

    private fun section(text: String) =
        mapOf(
            "type" to "section",
            "text" to mapOf("type" to "mrkdwn", "text" to text),
        )
}
