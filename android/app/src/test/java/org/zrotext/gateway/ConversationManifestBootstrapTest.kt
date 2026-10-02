// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class) @Config(sdk = [34])
class ConversationManifestBootstrapTest {
    private fun parsed(f: ConversationEnrollmentFixture): Pair<ConversationActivationCodec.Parsed, ByteArray> {
        val record = f.manifest.copyOfRange(151, 300)
        check(record[0] == 1.toByte())
        val digest = MessageDigest.getInstance("SHA-256").digest(f.manifest.copyOfRange(0, f.manifest.size - 64))
        val scope = ConversationInputFixture.scope.copy(accountId = f.account, deviceId = f.id(record.copyOfRange(98, 114)),
            lineId = f.id(record.copyOfRange(114, 130)), trustGeneration = 1, activationVersion = 2)
        return ConversationActivationCodec.Parsed(scope, ByteArray(32) { 2 }, f.now + 10000,
            1, digest, "fixture", "fixture", 1, 1) to record.copyOfRange(1, 33)
    }
    private fun denied(action: () -> Unit) {
        try { action(); fail("Expected refusal") } catch (_: IllegalArgumentException) {} catch (_: IllegalStateException) {}
    }
    @Test fun comparedRootAndAuthenticatedTimeInstallExactSignedGenesisPredecessor() {
        val f = ConversationEnrollmentFixture(); val trust = f.enrolled(); val (parsed, reader) = parsed(f)
        ConversationManifestBootstrap.install(trust, listOf(f.manifest), parsed, reader, { f.now }, {})
        assertEquals(1L, trust.inspect().snapshot!!.version)
        assertEquals(1L, trust.currentAuthority { f.now }.version)
    }
    @Test fun completedPrefixCanResumeTheSamePublicChainWithoutLoweringOrDuplicatingItsHighWater() {
        val f = ConversationEnrollmentFixture(); val trust = f.enrolled(); val (parsed, reader) = parsed(f)
        ConversationManifestBootstrap.install(trust, listOf(f.manifest), parsed, reader, { f.now }, {})
        val commits = f.storage.commits
        ConversationManifestBootstrap.install(trust, listOf(f.manifest), parsed, reader, { f.now }, {})
        assertEquals(commits, f.storage.commits); assertEquals(1L, trust.inspect().snapshot!!.version)
    }
    @Test fun wrongPredecessorOrReaderNeverCommitsEvenAnOtherwiseSignedChain() {
        val f = ConversationEnrollmentFixture(); val trust = f.enrolled(); val (parsed, reader) = parsed(f)
        val wrong = ConversationActivationCodec.Parsed(parsed.scope, parsed.signerId, parsed.expiresMs,
            1, ByteArray(32), parsed.site, parsed.instance, 1, 1)
        denied { ConversationManifestBootstrap.install(trust, listOf(f.manifest), wrong, reader, { f.now }, {}) }
        denied { ConversationManifestBootstrap.install(trust, listOf(f.manifest), parsed, ByteArray(32), { f.now }, {}) }
        assertEquals(0L, trust.inspect().snapshot!!.version)
    }
    @Test fun expiredHistoryIsRefusedWithoutWallClockFallbackOrTrustPromotion() {
        val f = ConversationEnrollmentFixture(); val trust = f.enrolled(); val (parsed, reader) = parsed(f)
        val expires = ByteBuffer.wrap(f.manifest, 45, 8).long
        denied { ConversationManifestBootstrap.install(trust, listOf(f.manifest), parsed, reader, { maxOf(expires, f.now + 86400001) }, {}) }
        assertEquals(0L, trust.inspect().snapshot!!.version)
    }
    @Test fun lifetimeLossDuringManifestPrecommitCannotAdvanceTheComparedRoot() {
        val f = ConversationEnrollmentFixture(); val trust = f.enrolled(); val (parsed, reader) = parsed(f)
        f.storage.beforeCommit = { f.live = false }
        denied { ConversationManifestBootstrap.install(trust, listOf(f.manifest), parsed, reader, { f.now }, { check(f.live) }) }
        assertEquals(0L, trust.inspect().snapshot!!.version)
    }
    private fun sign(key: KeyPair, unsigned: ByteArray): ByteArray = unsigned +
        Draft01SignaturePrimitive.canonicalRawFromDer(Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private); update("ZTSE/manifest/v2\u0000".toByteArray(Charsets.US_ASCII))
            update(ByteBuffer.allocate(4).putInt(unsigned.size).array()); update(unsigned); sign()
        })
    private fun chain(f: ConversationEnrollmentFixture): Pair<KeyPair, List<ByteArray>> {
        val root = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val point = DevicePayloadKeyStore.encodePoint(root.public as ECPublicKey)
        point.copyInto(f.pin, 29)
        val template = f.manifest.copyOfRange(0, f.manifest.size - 64)
        point.copyInto(template, 85)
        val owner = 151 + 149 * ((template[150].toInt() and 255) - 1)
        check(template[owner] == 6.toByte())
        point.copyInto(template, owner + 33)
        MessageDigest.getInstance("SHA-256").digest("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) +
            byteArrayOf(1, 1) + point).copyInto(template, owner + 1)
        var previous = ByteArray(32)
        val manifests = (1L..3L).map { version ->
            val unsigned = template.copyOf()
            ByteBuffer.wrap(unsigned, 29, 8).putLong(version); previous.copyInto(unsigned, 53)
            sign(root, unsigned).also { previous = MessageDigest.getInstance("SHA-256").digest(unsigned) }
        }
        manifests.first().copyInto(f.manifest)
        return root to manifests
    }
    private fun finalParsed(f: ConversationEnrollmentFixture, last: ByteArray): Pair<ConversationActivationCodec.Parsed, ByteArray> {
        val (first, reader) = parsed(f)
        val digest = MessageDigest.getInstance("SHA-256").digest(last.copyOfRange(0, last.size - 64))
        return ConversationActivationCodec.Parsed(first.scope.copy(activationVersion = 4), first.signerId, first.expiresMs,
            3, digest, first.site, first.instance, 1, 1) to reader
    }
    @Test fun interruptionAfterGenesisResumesRemainingSignedLinksFromTheExactStoredCheckpoint() {
        val f = ConversationEnrollmentFixture(); val (_, links) = chain(f); val trust = f.enrolled()
        val (parsed, reader) = finalParsed(f, links.last())
        f.storage.beforeCommit = { if (f.storage.commits == 2) f.live = false }
        denied { ConversationManifestBootstrap.install(trust, links, parsed, reader, { f.now }, { check(f.live) }) }
        assertEquals(1L, trust.inspect().snapshot!!.version)
        f.live = true; f.storage.beforeCommit = {}
        ConversationManifestBootstrap.install(trust, links, parsed, reader, { f.now }, { check(f.live) })
        assertEquals(3L, trust.inspect().snapshot!!.version); assertEquals(4, f.storage.commits)
    }
    @Test fun differentSignedCheckpointAndMalformedSkippedPrefixCannotResumeOrChangeStoredAuthority() {
        val f = ConversationEnrollmentFixture(); val (root, links) = chain(f); val trust = f.enrolled()
        val (firstParsed, reader) = parsed(f)
        ConversationManifestBootstrap.install(trust, listOf(links.first()), firstParsed, reader, { f.now }, {})
        val (parsed, _) = finalParsed(f, links.last())
        val changed = links.first().copyOfRange(0, links.first().size - 64)
        ByteBuffer.wrap(changed, 37, 8).putLong(f.now)
        denied { ConversationManifestBootstrap.install(trust, listOf(sign(root, changed)) + links.drop(1), parsed, reader, { f.now }, {}) }
        val malformed = links.first().copyOf().also { it[0] = 0 }
        denied { ConversationManifestBootstrap.install(trust, listOf(malformed) + links.drop(1), parsed, reader, { f.now }, {}) }
        assertEquals(1L, trust.inspect().snapshot!!.version); assertEquals(2, f.storage.commits)
    }
}
