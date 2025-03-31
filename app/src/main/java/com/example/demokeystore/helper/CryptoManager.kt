package com.example.demokeystore.helper

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class CryptoManager {

    // init for keystore
    companion object {
        private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC
        private const val PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7
        private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
    }

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private val parameterSpec = KeyGenParameterSpec.Builder("secret",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(BLOCK_MODE)
        .setEncryptionPaddings(PADDING)
        .setUserAuthenticationRequired(true) // false if don't use biometric
        .setRandomizedEncryptionRequired(true)
        .build()

    private fun createKey() : SecretKey {
        val keyGenerator = KeyGenerator.getInstance(ALGORITHM)
        keyGenerator.init(parameterSpec)
        return keyGenerator.generateKey()
    }

    private fun getKey() : SecretKey {
        val existingKey = keyStore.getEntry("secret", null) as? KeyStore.SecretKeyEntry
        return existingKey?.secretKey ?: createKey()
    }

    private val encryptCipher: Cipher = Cipher.getInstance(TRANSFORMATION).apply {
        init(Cipher.ENCRYPT_MODE, getKey())
    }

    private fun getDecryptCipherForIv(iv: ByteArray) = Cipher.getInstance(TRANSFORMATION).apply {
        init(Cipher.DECRYPT_MODE, getKey(), IvParameterSpec(iv))
    }

    fun encrypt(plaintext: String, outputStream: OutputStream): ByteArray {
        val bytes = plaintext.toByteArray(Charsets.UTF_8)
        val ciphertext = encryptCipher.doFinal(bytes)
        outputStream.use {
            it.write(encryptCipher.iv.size)
            it.write(encryptCipher.iv)
            it.write(ciphertext.size)
            it.write(ciphertext)
        }
        return ciphertext
    }

    fun decrypt(inputStream: InputStream) : String {
        return inputStream.use {
            val ivSize = it.read()
            val iv = ByteArray(ivSize)
            it.read(iv)

            val encryptedBytesSize = it.read()
            val encryptedBytes = ByteArray(encryptedBytesSize)
            it.read(encryptedBytes)

            getDecryptCipherForIv(iv).doFinal(encryptedBytes).toString(Charsets.UTF_8)
        }
    }

    // Get a Cipher for decryption that can be used with biometric authentication
    fun getDecryptCipher(): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getKey())
        return cipher
    }

    // Decrypt data using a provided cipher (after biometric authentication)
    fun decryptWithCipher(inputStream: InputStream, cipher: Cipher): String {
        return inputStream.use {
            // Read the IV size and IV from the input stream
            val ivSize = it.read()
            val iv = ByteArray(ivSize)
            it.read(iv)

            // Read the encrypted data size and the encrypted data
            val encryptedBytesSize = it.read()
            val encryptedBytes = ByteArray(encryptedBytesSize)
            it.read(encryptedBytes)

            // Initialize the cipher with the IV from the file
            // Note: For BiometricPrompt CryptoObject, we may need to handle this differently
            // depending on how the cipher was initialized before authentication
            try {
                val decryptedBytes = cipher.doFinal(encryptedBytes)
                decryptedBytes.toString(Charsets.UTF_8)
            } catch (e: Exception) {
                // If the cipher wasn't initialized with IV yet, initialize it and then decrypt
                cipher.init(Cipher.DECRYPT_MODE, getKey(), IvParameterSpec(iv))
                val decryptedBytes = cipher.doFinal(encryptedBytes)
                decryptedBytes.toString(Charsets.UTF_8)
            }
        }
    }
}