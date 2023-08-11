package com.carriez.flutter_hbb

import android.util.Base64
import java.security.MessageDigest
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


fun String.md5(): String {
    return try {
        val md5 = MessageDigest.getInstance("MD5")
        md5.digest(this.toByteArray()).toHex()
    } catch (e: Exception) {
        ""
    }
}

private val HEX_CHARS = "0123456789ABCDEF".toCharArray()
private fun ByteArray.toHex(): String {
    val result = StringBuilder(size * 2)
    forEach { b ->
        val i = b.toInt()
        result.append(HEX_CHARS[i shr 4 and 0xF])
        result.append(HEX_CHARS[i and 0xF])
    }
    return result.toString()
}

fun String?.encrypt(): String {
    return if (this.isNullOrEmpty()) {
        ""
    } else {
        try {
            val bytes = symmetricTemplate(
                this.toByteArray(), KEY, "AES", "AES/CBC/PKCS7Padding", IV, true
            )
            String(Base64.encode(bytes, Base64.NO_WRAP))
        } catch (e: Exception) {
            ""
        }
    }
}

fun String?.decrypt(): String {
    return if (this.isNullOrEmpty()) {
        ""
    } else {
        try {
            val bytes = symmetricTemplate(
                Base64.decode(this.toByteArray(), Base64.NO_WRAP),
                KEY, "AES", "AES/CBC/PKCS7Padding", IV, false
            )
            String(bytes)
        } catch (e: Exception) {
            ""
        }
    }
}

@Suppress("SameParameterValue")
private fun symmetricTemplate(
    data: ByteArray?,
    key: ByteArray?,
    algorithm: String,
    transformation: String,
    iv: ByteArray?,
    isEncrypt: Boolean
): ByteArray {
    return if (data == null || data.isEmpty() || key == null || key.isEmpty()) byteArrayOf()
    else try {
        val secretKey: SecretKey = if ("DES" == algorithm) {
            val desKey = DESKeySpec(key)
            val keyFactory = SecretKeyFactory.getInstance(algorithm)
            keyFactory.generateSecret(desKey)
        } else {
            SecretKeySpec(key, algorithm)
        }
        val cipher = Cipher.getInstance(transformation)
        if (iv == null || iv.isEmpty()) {
            cipher.init(if (isEncrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, secretKey)
        } else {
            val params: AlgorithmParameterSpec = IvParameterSpec(iv)
            cipher.init(
                if (isEncrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE,
                secretKey,
                params
            )
        }
        cipher.doFinal(data)
    } catch (e: Throwable) {
        e.printStackTrace()
        byteArrayOf()
    }
}

private val KEY = "6CE32BCC90578829".toByteArray()
private val IV = "D1501DFEA4094DDA".toByteArray()