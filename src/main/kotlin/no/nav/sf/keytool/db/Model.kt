package no.nav.sf.keytool.db

import no.nav.sf.keytool.cert.CertMetadata
import org.jetbrains.exposed.sql.ResultRow
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.javatime.timestamp

const val CERT_METADATA = "cert_metadata"

object CertMetadataTable : Table(CERT_METADATA) {
    val cn = varchar("cn", 255).uniqueIndex()
    val expiresAt = timestamp("expires_at")
    val sfClientId = varchar("sf_client_id", 20).nullable()
    val sfUsername = varchar("sf_username", 255).nullable()
}

fun ResultRow.toCertMetadata() =
    CertMetadata(
        cn = this[CertMetadataTable.cn],
        expiresAt = this[CertMetadataTable.expiresAt],
        sfClientId = this[CertMetadataTable.sfClientId],
        sfUsername = this[CertMetadataTable.sfUsername],
    )
