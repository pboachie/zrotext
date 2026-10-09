// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class LineActivationV2Test {
    // Encoding-only DER r=1,s=1. It is NOT a valid signature over any statement below.
    private val placeholderDer = hex("3006020101020101")
    private fun id(value: Int) = UUID(0x4000L, Long.MIN_VALUE or value.toLong())
    private fun row(kind: LineActivationV2Kind, card: Int, profile: Int, port: Int, slot: Int) =
        LineActivationV2Row(kind, id(card), id(profile), port, slot)
    private fun base() = listOf(row(LineActivationV2Kind.PHYSICAL, 0x10, 0x20, 0, 0),
        row(LineActivationV2Kind.EMBEDDED, 0x11, 0x21, 0, 1))
    private fun dual() = listOf(row(LineActivationV2Kind.EMBEDDED, 0x12, 0x22, 0, 0),
        row(LineActivationV2Kind.EMBEDDED, 0x12, 0x23, 1, 0))
    private fun set(rows: List<LineActivationV2Row> = base(), epoch: Long = 1, api: Int = 33,
        monitor: UUID = id(0x40)) = LineActivationV2CompleteSet(monitor, epoch, api, rows)
    private fun fields(generation: Long = 1, nonce: ByteArray = ByteArray(32) { it.toByte() }) =
        LineActivationV2StatementFields(id(1), id(2), id(3), generation, id(4), nonce)
    private fun observation() = set().observation(base()[0], 7, id(0x41))
    private fun declaration(purpose: LineActivationV2Purpose = LineActivationV2Purpose.SMS,
        epoch: Long = 1) = LineActivationV2Frames.ProofDeclaration(purpose, epoch, id(4),
        observation(), placeholderDer)
    private fun frame(purpose: LineActivationV2Purpose = LineActivationV2Purpose.SMS) =
        JSONObject(LineActivationV2Frames.proof(declaration(purpose)))
    private fun reject(action: () -> Unit) { assertThrows(IllegalArgumentException::class.java) { action() } }
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun sha(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
    private fun changedBody(offset: Int, update: (ByteBuffer) -> Unit): ByteArray =
        observation().bytes().also { update(ByteBuffer.wrap(it).apply { position(offset) }) }

    private data class Literal(val name: String, val purpose: LineActivationV2Purpose,
        val generation: Long, val epoch: Long, val subscription: Int, val profile: UUID,
        val commitment: String, val observation: String, val base64: String,
        val device: String, val owner: String)
    private val literals = listOf(
        Literal("sms-physical-selected-peer-esim-active", LineActivationV2Purpose.SMS, 1L, 1L, 7, UUID.fromString("00000000-0000-4000-8000-000000000020"),
            "893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
            "0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
            "ACEAAgAAAAcBAAAAAAAAQACAAAAAAAAAEAAAAAAAAEAAgAAAAAAAACAAAAAAAAAAAAAAAAAAAEAAgAAAAAAAAEAAAAAAAAAAAQAAAAAAAEAAgAAAAAAAAEGJMgWr3czL5mT8u6V4vrqEukozVMXfGzmtxn0Nq1zAFw",
            "5a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
            "5a54534d532f6c696e652f6f776e65722d617070726f76652f7632005a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc01757093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675"),
        Literal("sms-esim-selected-peer-physical-active", LineActivationV2Purpose.SMS, 1L, 1L, 11, UUID.fromString("00000000-0000-4000-8000-000000000021"),
            "893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
            "002100020000000b020000000000004000800000000000001100000000000040008000000000000021000000000000000100000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
            "ACEAAgAAAAsCAAAAAAAAQACAAAAAAAAAEQAAAAAAAEAAgAAAAAAAACEAAAAAAAAAAQAAAAAAAEAAgAAAAAAAAEAAAAAAAAAAAQAAAAAAAEAAgAAAAAAAAEGJMgWr3czL5mT8u6V4vrqEukozVMXfGzmtxn0Nq1zAFw",
            "5a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000b020000000000004000800000000000001100000000000040008000000000000021000000000000000100000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
            "5a54534d532f6c696e652f6f776e65722d617070726f76652f7632005a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000b020000000000004000800000000000001100000000000040008000000000000021000000000000000100000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc01757093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675"),
        Literal("sms-dual-esim-same-card-slot-port0-selected", LineActivationV2Purpose.SMS, 1L, 1L, 9, UUID.fromString("00000000-0000-4000-8000-000000000022"),
            "5cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
            "00210002000000090200000000000040008000000000000012000000000000400080000000000000220000000000000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
            "ACEAAgAAAAkCAAAAAAAAQACAAAAAAAAAEgAAAAAAAEAAgAAAAAAAACIAAAAAAAAAAAAAAAAAAEAAgAAAAAAAAEAAAAAAAAAAAQAAAAAAAEAAgAAAAAAAAEFctcH_5G8wo3akWNsN9aIsVqgVJL6yb5zLnb-x9u3NKw",
            "5a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00210002000000090200000000000040008000000000000012000000000000400080000000000000220000000000000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
            "5a54534d532f6c696e652f6f776e65722d617070726f76652f7632005a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00210002000000090200000000000040008000000000000012000000000000400080000000000000220000000000000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b57093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675"),
        Literal("sms-dual-esim-same-card-slot-port1-selected", LineActivationV2Purpose.SMS, 1L, 1L, 10, UUID.fromString("00000000-0000-4000-8000-000000000023"),
            "5cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
            "002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
            "ACEAAgAAAAoCAAAAAAAAQACAAAAAAAAAEgAAAAAAAEAAgAAAAAAAACMAAAABAAAAAAAAAAAAAEAAgAAAAAAAAEAAAAAAAAAAAQAAAAAAAEAAgAAAAAAAAEFctcH_5G8wo3akWNsN9aIsVqgVJL6yb5zLnb-x9u3NKw",
            "5a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
            "5a54534d532f6c696e652f6f776e65722d617070726f76652f7632005a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b57093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675"),
        Literal("sealed-physical-selected-peer-esim-active", LineActivationV2Purpose.SEALED, 1L, 1L, 7, UUID.fromString("00000000-0000-4000-8000-000000000020"),
            "893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
            "0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
            "ACEAAgAAAAcBAAAAAAAAQACAAAAAAAAAEAAAAAAAAEAAgAAAAAAAACAAAAAAAAAAAAAAAAAAAEAAgAAAAAAAAEAAAAAAAAAAAQAAAAAAAEAAgAAAAAAAAEGJMgWr3czL5mT8u6V4vrqEukozVMXfGzmtxn0Nq1zAFw",
            "5a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
            "5a5453452f6c696e652f6f776e65722d617070726f76652f7632005a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc01757093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675"),
        Literal("sealed-esim-selected-peer-physical-active", LineActivationV2Purpose.SEALED, 1L, 1L, 11, UUID.fromString("00000000-0000-4000-8000-000000000021"),
            "893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
            "002100020000000b020000000000004000800000000000001100000000000040008000000000000021000000000000000100000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
            "ACEAAgAAAAsCAAAAAAAAQACAAAAAAAAAEQAAAAAAAEAAgAAAAAAAACEAAAAAAAAAAQAAAAAAAEAAgAAAAAAAAEAAAAAAAAAAAQAAAAAAAEAAgAAAAAAAAEGJMgWr3czL5mT8u6V4vrqEukozVMXfGzmtxn0Nq1zAFw",
            "5a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000b020000000000004000800000000000001100000000000040008000000000000021000000000000000100000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017",
            "5a5453452f6c696e652f6f776e65722d617070726f76652f7632005a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000b020000000000004000800000000000001100000000000040008000000000000021000000000000000100000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc01757093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675"),
        Literal("sealed-dual-esim-same-card-slot-port0-selected", LineActivationV2Purpose.SEALED, 1L, 1L, 9, UUID.fromString("00000000-0000-4000-8000-000000000022"),
            "5cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
            "00210002000000090200000000000040008000000000000012000000000000400080000000000000220000000000000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
            "ACEAAgAAAAkCAAAAAAAAQACAAAAAAAAAEgAAAAAAAEAAgAAAAAAAACIAAAAAAAAAAAAAAAAAAEAAgAAAAAAAAEAAAAAAAAAAAQAAAAAAAEAAgAAAAAAAAEFctcH_5G8wo3akWNsN9aIsVqgVJL6yb5zLnb-x9u3NKw",
            "5a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00210002000000090200000000000040008000000000000012000000000000400080000000000000220000000000000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
            "5a5453452f6c696e652f6f776e65722d617070726f76652f7632005a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00210002000000090200000000000040008000000000000012000000000000400080000000000000220000000000000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b57093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675"),
        Literal("sealed-dual-esim-same-card-slot-port1-selected", LineActivationV2Purpose.SEALED, 1L, 1L, 10, UUID.fromString("00000000-0000-4000-8000-000000000023"),
            "5cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
            "002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
            "ACEAAgAAAAoCAAAAAAAAQACAAAAAAAAAEgAAAAAAAEAAgAAAAAAAACMAAAABAAAAAAAAAAAAAEAAgAAAAAAAAEAAAAAAAAAAAQAAAAAAAEAAgAAAAAAAAEFctcH_5G8wo3akWNsN9aIsVqgVJL6yb5zLnb-x9u3NKw",
            "5a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b",
            "5a5453452f6c696e652f6f776e65722d617070726f76652f7632005a5453452f6c696e652f6465766963652d636f6e6669726d2f7632000202000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000400000000000000001000000000000400080000000000000415cb5c1ffe46f30a376a458db0df5a22c56a81524beb26f9ccb9dbfb1f6edcd2b57093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675"),
        Literal("sms-count256-encoding-boundary-not-hardware-claim", LineActivationV2Purpose.SMS, 1L, 1L, 255, UUID.fromString("00000000-0000-4000-8000-0000000010ff"),
            "db974c0a6bc2a924e87c076d5e5391ea1d4620636b185019a2b4122af3acb55b",
            "00210100000000ff02000000000000400080000000000001ff000000000000400080000000000010ff00000000000000ff00000000000040008000000000000040000000000000000100000000000040008000000000000041db974c0a6bc2a924e87c076d5e5391ea1d4620636b185019a2b4122af3acb55b",
            "ACEBAAAAAP8CAAAAAAAAQACAAAAAAAAB_wAAAAAAAEAAgAAAAAAAEP8AAAAAAAAA_wAAAAAAAEAAgAAAAAAAAEAAAAAAAAAAAQAAAAAAAEAAgAAAAAAAAEHbl0wKa8KpJOh8B21eU5HqHUYgY2sYUBmitBIq86y1Ww",
            "5a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00210100000000ff02000000000000400080000000000001ff000000000000400080000000000010ff00000000000000ff00000000000040008000000000000040000000000000000100000000000040008000000000000041db974c0a6bc2a924e87c076d5e5391ea1d4620636b185019a2b4122af3acb55b",
            "5a54534d532f6c696e652f6f776e65722d617070726f76652f7632005a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00210100000000ff02000000000000400080000000000001ff000000000000400080000000000010ff00000000000000ff00000000000040008000000000000040000000000000000100000000000040008000000000000041db974c0a6bc2a924e87c076d5e5391ea1d4620636b185019a2b4122af3acb55b57093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675"),
        Literal("sealed-positive-i64-maximum-encoding-boundary", LineActivationV2Purpose.SEALED, 9223372036854775807L, 9223372036854775807L, 10, UUID.fromString("00000000-0000-4000-8000-000000000023"),
            "a10f35a0ef007c113f0a889b0442984aa728fbf2022427bacaf7e8f5bf10b403",
            "002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000407fffffffffffffff00000000000040008000000000000041a10f35a0ef007c113f0a889b0442984aa728fbf2022427bacaf7e8f5bf10b403",
            "ACEAAgAAAAoCAAAAAAAAQACAAAAAAAAAEgAAAAAAAEAAgAAAAAAAACMAAAABAAAAAAAAAAAAAEAAgAAAAAAAAEB__________wAAAAAAAEAAgAAAAAAAAEGhDzWg7wB8ET8KiJsEQphKpyj78gIkJ7rK9-j1vxC0Aw",
            "5a5453452f6c696e652f6465766963652d636f6e6669726d2f76320002020000000000004000800000000000000100000000000040008000000000000002000000000000400080000000000000037fffffffffffffff00000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000407fffffffffffffff00000000000040008000000000000041a10f35a0ef007c113f0a889b0442984aa728fbf2022427bacaf7e8f5bf10b403",
            "5a5453452f6c696e652f6f776e65722d617070726f76652f7632005a5453452f6c696e652f6465766963652d636f6e6669726d2f76320002020000000000004000800000000000000100000000000040008000000000000002000000000000400080000000000000037fffffffffffffff00000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f002100020000000a0200000000000040008000000000000012000000000000400080000000000000230000000100000000000000000000400080000000000000407fffffffffffffff00000000000040008000000000000041a10f35a0ef007c113f0a889b0442984aa728fbf2022427bacaf7e8f5bf10b40357093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675"),
        Literal("sms-same-count-peer-replacement", LineActivationV2Purpose.SMS, 1L, 1L, 7, UUID.fromString("00000000-0000-4000-8000-000000000020"),
            "db062bc2f8535bbf32bc07507505e67745611fc360c480cda114f3e52ea1f20b",
            "0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041db062bc2f8535bbf32bc07507505e67745611fc360c480cda114f3e52ea1f20b",
            "ACEAAgAAAAcBAAAAAAAAQACAAAAAAAAAEAAAAAAAAEAAgAAAAAAAACAAAAAAAAAAAAAAAAAAAEAAgAAAAAAAAEAAAAAAAAAAAQAAAAAAAEAAgAAAAAAAAEHbBivC-FNbvzK8B1B1BeZ3RWEfw2DEgM2hFPPlLqHyCw",
            "5a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041db062bc2f8535bbf32bc07507505e67745611fc360c480cda114f3e52ea1f20b",
            "5a54534d532f6c696e652f6f776e65722d617070726f76652f7632005a54534d532f6c696e652f6465766963652d636f6e6669726d2f7632000201000000000000400080000000000000010000000000004000800000000000000200000000000040008000000000000003000000000000000100000000000040008000000000000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0021000200000007010000000000004000800000000000001000000000000040008000000000000020000000000000000000000000000040008000000000000040000000000000000100000000000040008000000000000041db062bc2f8535bbf32bc07507505e67745611fc360c480cda114f3e52ea1f20b57093944c2f730f5d554173cb3555795c1a4f68c647be0ff8e3adb840b757675")
    )
    private fun rowsFor(name: String): List<LineActivationV2Row> = when {
        "count256" in name -> (0 until 256).map {
            row(LineActivationV2Kind.EMBEDDED, 0x100 + it, 0x1000 + it, 0, it)
        }
        "dual-esim" in name || "i64-maximum" in name -> dual()
        "peer-replacement" in name -> base().let { listOf(it[0], it[1].copy(profileToken = id(0x24))) }
        else -> base()
    }
    @Test fun allElevenLiteralStatementsMatchEncodingOnlyVectors() {
        assertEquals(11, literals.size)
        for (literal in literals) {
            val rows = rowsFor(literal.name)
            val full = set(rows, literal.epoch)
            val selected = rows.single { it.profileToken == literal.profile }
            val observed = full.observation(selected, literal.subscription, id(0x41))
            val device = LineActivationV2Statements.device(literal.purpose, fields(literal.generation), observed)
            assertArrayEquals(literal.name, hex(literal.commitment), full.commitment())
            assertArrayEquals(literal.name, hex(literal.observation), observed.bytes())
            assertEquals(literal.base64, Base64.getUrlEncoder().withoutPadding().encodeToString(observed.bytes()))
            assertArrayEquals(literal.name, hex(literal.device), device)
            assertArrayEquals(literal.name, hex(literal.owner),
                LineActivationV2Statements.owner(literal.purpose, device, placeholderDer))
            assertEquals(if (literal.purpose == LineActivationV2Purpose.SMS) 256 else 255, device.size)
        }
    }
    @Test fun physicalAndEmbeddedSelectionsKeepPeersInSameCommitment() {
        for (rows in listOf(base(), dual())) {
            val full = set(rows)
            val first = full.observation(rows[0], 7, id(0x41)).bytes()
            val second = full.observation(rows[1], 11, id(0x42)).bytes()
            assertEquals(2, ByteBuffer.wrap(first).getShort(2).toInt())
            assertEquals(2, ByteBuffer.wrap(second).getShort(2).toInt())
            assertArrayEquals(first.copyOfRange(89, 121), second.copyOfRange(89, 121))
            assertFalse(first.contentEquals(second))
        }
    }
    @Test fun unsignedTokenSortingIsCanonicalAcrossInputOrderAndSignBit() {
        val rows = listOf(base()[0].copy(profileToken = UUID(Long.MIN_VALUE, 1)),
            base()[1].copy(profileToken = UUID(1, 1)))
        val first = set(rows).preimage()
        assertArrayEquals(first, set(rows.reversed()).preimage())
        val start = "ZT/line/complete-set/v2\u0000".toByteArray(Charsets.US_ASCII).size + 28
        assertEquals(1L, ByteBuffer.wrap(first).getLong(start + 17))
    }
    @Test fun sameCountReplacementEpochAndMonitorChangeCommitment() {
        val rows = base()
        val original = set(rows).commitment()
        assertFalse(original.contentEquals(set(listOf(rows[0], rows[1].copy(profileToken = id(0x24)))).commitment()))
        assertFalse(original.contentEquals(set(rows, epoch = 2).commitment()))
        assertFalse(original.contentEquals(set(rows, monitor = id(0x42)).commitment()))
    }
    @Test fun rowDuplicatesMissingSelectionAndInvalidMappingsRefuse() {
        val rows = base()
        reject { set(listOf(rows[0], rows[1].copy(profileToken = rows[0].profileToken))) }
        reject { set(listOf(dual()[0], dual()[1].copy(portIndex = 0))) }
        reject { set().observation(dual()[0], 7, id(0x41)) }
        reject { rows[0].copy(cardToken = UUID(0, 0)) }
        reject { rows[0].copy(profileToken = UUID(0, 0)) }
        reject { rows[0].copy(portIndex = -1) }
        reject { rows[0].copy(slotIndex = -1) }
    }
    @Test fun completeSetApiCountAndLifetimeBoundsRefuse() {
        reject { set(emptyList()) }
        reject { set((0..256).map { row(LineActivationV2Kind.EMBEDDED, it + 1, it + 1, 0, it) }) }
        for (api in listOf(0, 32, 65536)) reject { set(api = api) }
        for (epoch in listOf(0L, -1L)) reject { set(epoch = epoch) }
        reject { set(monitor = UUID(0, 0)) }
        reject { set().observation(base()[0], -1, id(0x41)) }
        reject { set().observation(base()[0], 7, UUID(0, 0)) }
        assertEquals(65535, ByteBuffer.wrap(set(api = 65535).observation(base()[0], 7, id(0x41)).bytes()).short.toInt() and 0xffff)
    }
    @Test fun observationDecodeRejectsLengthBoundsKindNilTokensAndNegativeMappings() {
        reject { LineActivationV2Observation.decode(observation().bytes() + 0) }
        reject { LineActivationV2Observation.decode(observation().bytes().dropLast(1).toByteArray()) }
        val invalid = listOf(
            changedBody(0) { it.putShort(32) }, changedBody(2) { it.putShort(0) },
            changedBody(2) { it.putShort(257) }, changedBody(4) { it.putInt(-1) },
            changedBody(8) { it.put(3) }, changedBody(9) { it.putLong(0).putLong(0) },
            changedBody(25) { it.putLong(0).putLong(0) }, changedBody(41) { it.putInt(-1) },
            changedBody(45) { it.putInt(-1) }, changedBody(49) { it.putLong(0).putLong(0) },
            changedBody(65) { it.putLong(0) }, changedBody(73) { it.putLong(0).putLong(0) })
        for (bytes in invalid) reject { LineActivationV2Observation.decode(bytes) }
    }
    @Test fun statementFieldsRefuseNilIdentityGenerationAndNonceLength() {
        for (generation in listOf(0L, -1L)) reject { fields(generation) }
        for (size in listOf(0, 31, 33)) reject { fields(nonce = ByteArray(size)) }
        for (index in 0..3) {
            val ids = MutableList(4) { id(it + 1) }.also { it[index] = UUID(0, 0) }
            reject { LineActivationV2StatementFields(ids[0], ids[1], ids[2], 1, ids[3], ByteArray(32)) }
        }
    }
    @Test fun ownerAndProofDigestRejectCrossPurposeTrailingAndMalformedDeviceBytes() {
        val sms = LineActivationV2Statements.device(LineActivationV2Purpose.SMS, fields(), observation())
        reject { LineActivationV2Statements.owner(LineActivationV2Purpose.SEALED, sms, placeholderDer) }
        reject { LineActivationV2Statements.proofDigest(LineActivationV2Purpose.SEALED, sms, placeholderDer) }
        reject { LineActivationV2Statements.owner(LineActivationV2Purpose.SMS, sms + 0, placeholderDer) }
        val malformedStatements = listOf(
            sms.copyOf().also { it[0] = 0 }, sms.copyOf().also { it[29] = 0 },
            sms.copyOf().also { it[30] = 0 }, sms.copyOf().also { it.fill(0, 31, 47) },
            sms.copyOf().also { it.fill(0, 79, 87) },
            sms.copyOf().also { ByteBuffer.wrap(it).putShort(135, 32) })
        for (malformed in malformedStatements) {
            reject { LineActivationV2Statements.owner(LineActivationV2Purpose.SMS, malformed, placeholderDer) }
        }
        assertArrayEquals(sha(sms + placeholderDer),
            LineActivationV2Statements.proofDigest(LineActivationV2Purpose.SMS, sms, placeholderDer))
    }
    @Test fun canonicalDerUsesExistingParserWithoutInventedLowSPolicy() {
        val sms = LineActivationV2Statements.device(LineActivationV2Purpose.SMS, fields(), observation())
        for (bad in listOf(placeholderDer + 0, hex("300702020001020101"), hex("3006020100020101"))) {
            reject { LineActivationV2Statements.owner(LineActivationV2Purpose.SMS, sms, bad) }
            reject { LineActivationV2Frames.ProofDeclaration(LineActivationV2Purpose.SMS, 1, id(4), observation(), bad) }
        }
        // Canonical high-s is structurally allowed by the existing interop policy; no verification claim.
        val highS = hex("3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550")
        assertEquals(316, LineActivationV2Statements.owner(LineActivationV2Purpose.SMS, sms, highS).size)
    }
    @Test fun declarationInputsAndReturnedArraysAreDefensiveCopies() {
        val rows = base().toMutableList()
        val full = set(rows)
        val preimage = full.preimage()
        rows.clear()
        assertArrayEquals(preimage, full.preimage())
        val nonce = ByteArray(32) { it.toByte() }
        val tupleFields = fields(nonce = nonce)
        val tuple = tupleFields.tuple()
        nonce.fill(0); tupleFields.tuple().fill(0)
        assertArrayEquals(tuple, tupleFields.tuple())
        val bytes = observation().bytes()
        val observed = LineActivationV2Observation.decode(bytes)
        val expected = observed.bytes()
        bytes.fill(0); observed.bytes().fill(0)
        assertArrayEquals(expected, observed.bytes())
        val der = placeholderDer.copyOf()
        val proof = LineActivationV2Frames.ProofDeclaration(LineActivationV2Purpose.SMS, 1, id(4), observed, der)
        der.fill(0); proof.signatureDer().fill(0)
        assertArrayEquals(placeholderDer, proof.signatureDer())
    }
    @Test fun bothClosedProofShapesRoundTripBoundedDeclarationsOnly() {
        for (purpose in LineActivationV2Purpose.entries) {
            val emitted = LineActivationV2Frames.proof(declaration(purpose, Long.MAX_VALUE))
            assertTrue(emitted.toByteArray(Charsets.UTF_8).size < 4096)
            val json = JSONObject(emitted)
            assertEquals(setOf("type", "v", "connection_epoch", "challenge_id", "observation_b64url", "signature_der"),
                json.keys().asSequence().toSet())
            assertEquals(purpose.proofType(), json.getString("type"))
            assertEquals(Long.MAX_VALUE.toString(), json.getString("connection_epoch"))
            assertEquals(162, json.getString("observation_b64url").length)
            val parsed = LineActivationV2Frames.parseProof(json, purpose)
            assertEquals(Long.MAX_VALUE, parsed.connectionEpoch)
            assertArrayEquals(observation().bytes(), parsed.observation.bytes())
            assertArrayEquals(placeholderDer, parsed.signatureDer())
        }
    }
    @Test fun proofClosureVersionAndPurposeRejectExtraMissingAndUnimplementedShapes() {
        val original = frame()
        for (key in original.keys().asSequence().toList()) {
            reject { LineActivationV2Frames.parseProof(JSONObject(original.toString()).also { it.remove(key) }, LineActivationV2Purpose.SMS) }
        }
        reject { LineActivationV2Frames.parseProof(JSONObject(original.toString()).put("accepted", true), LineActivationV2Purpose.SMS) }
        for (version in listOf(1, 3, "2", 2.0, true, JSONObject.NULL)) {
            reject { LineActivationV2Frames.parseProof(JSONObject(original.toString()).put("v", version), LineActivationV2Purpose.SMS) }
        }
        val unimplemented = listOf("sms_line_challenge_v2", "sms_line_proof_ack_v2", "sms_line_activated_v2",
            "sealed_line_challenge_v2", "sealed_line_proof_ack_v2", "sealed_line_activated_v2",
            "sealed_line_installed_v2", "sealed_line_install_ack_v2", "sms_line_proof")
        for (type in unimplemented) reject {
            LineActivationV2Frames.parseProof(JSONObject(original.toString()).put("type", type), LineActivationV2Purpose.SMS)
        }
        reject { LineActivationV2Frames.parseProof(original, LineActivationV2Purpose.SEALED) }
    }
    @Test fun positiveDecimalEpochRejectsLossyNumbersNoncanonicalTextAndOverflow() {
        val original = frame()
        for (value in listOf<Any>(0, 1, 1L, 1.0, true, JSONObject.NULL, "0", "01", "+1", "-1", "1e1", "1.0", " 1", "9223372036854775808")) {
            reject { LineActivationV2Frames.parseProof(JSONObject(original.toString()).put("connection_epoch", value), LineActivationV2Purpose.SMS) }
        }
        assertEquals(Long.MAX_VALUE, LineActivationV2Frames.positiveDecimal(Long.MAX_VALUE.toString()))
        assertEquals(1L, LineActivationV2Frames.positiveDecimal("1"))
    }
    @Test fun proofUuidAndBase64RejectNoncanonicalAndOversizedValues() {
        val original = frame()
        for (value in listOf<Any>(UUID(0, 0).toString(), "1-1-1-1-1", 1, JSONObject.NULL)) {
            reject { LineActivationV2Frames.parseProof(JSONObject(original.toString()).put("challenge_id", value), LineActivationV2Purpose.SMS) }
        }
        reject { LineActivationV2Frames.parseProof(JSONObject(original.toString()).put("challenge_id", "00000000-0000-4000-8000-0000000000AB"), LineActivationV2Purpose.SMS) }
        for (key in listOf("observation_b64url", "signature_der")) {
            val encoded = original.getString(key)
            for (value in listOf<Any>(encoded + "=", encoded.dropLast(1), "", "A".repeat(5000), 1, JSONObject.NULL)) {
                reject { LineActivationV2Frames.parseProof(JSONObject(original.toString()).put(key, value), LineActivationV2Purpose.SMS) }
            }
        }
        val changed = original.getString("observation_b64url").dropLast(1) + "B"
        reject { LineActivationV2Frames.parseProof(JSONObject(original.toString()).put("observation_b64url", changed), LineActivationV2Purpose.SMS) }
    }
    @Test fun diagnosticsRemainRedactedAndDoNotClaimAuthority() {
        for (value in listOf(base()[0], set(), observation(), fields(), declaration())) {
            assertTrue(value.toString().contains("redacted"))
            assertFalse(value.toString().contains(id(4).toString()))
        }
    }
}
