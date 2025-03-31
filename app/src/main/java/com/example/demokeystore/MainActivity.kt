package com.example.demokeystore

import android.content.ContentValues.TAG
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.example.demokeystore.helper.CryptoManager
import java.io.File
import java.util.concurrent.Executor


class MainActivity : AppCompatActivity() {

    private lateinit var encryptButton: Button
    private lateinit var decryptButton: Button
    private lateinit var biometricButton: Button
    private lateinit var editText: EditText
    private lateinit var resultTextView: TextView
    private val cryptoManager = CryptoManager()
    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        encryptButton = findViewById(R.id.encryptButton)
        decryptButton = findViewById(R.id.decryptButton)
        editText = findViewById(R.id.editText)
        resultTextView = findViewById(R.id.resultTextView)
        biometricButton = findViewById(R.id.biometricButton)

        encryptButton.setOnClickListener {
            val plaintext = editText.text.toString()
            val file = File(filesDir, "secret.txt")
            if (!file.exists()) {
                file.createNewFile()
            }
            val fos = file.outputStream()
            resultTextView.text = cryptoManager.encrypt(plaintext, fos).toString()
        }

        decryptButton.setOnClickListener {
            val file = File(filesDir, "secret.txt")
            val decrypted = cryptoManager.decrypt(file.inputStream())
            editText.setText(decrypted)
        }

        // Initialize biometric components
        setupBiometricAuthentication()

        biometricButton.setOnClickListener {
            startBiometricAuthentication()
        }
    }

    private fun setupBiometricAuthentication() {

        val manager = BiometricManager.from(this)


        val canAuthenticate = manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        when (canAuthenticate) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                Log.d(TAG, "Biometric features are available")
            }
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                Log.e(TAG, "No biometric features available on this device")
            }
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                Log.e(TAG, "Biometric features are currently unavailable")
            }
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                Log.e(TAG, "No biometric credentials are enrolled")
            }
            else -> {
                Log.e(TAG, "Biometric status: $canAuthenticate")
            }
        }


        executor = ContextCompat.getMainExecutor(this)

        biometricPrompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)

                    // Get the Cipher from the CryptoObject
                    val cryptoObject = result.cryptoObject
                    val cipher = cryptoObject?.cipher

                    Log.d("ok123", "Authentication succeeded")

                    if (cipher != null) {
                        try {
                            // Read the encrypted file
                            val file = File(filesDir, "secret.txt")
                            if (file.exists()) {
                                val decryptedData = cryptoManager.decryptWithCipher(file.inputStream(), cipher)
                                resultTextView.text = decryptedData
                                Log.d("Biometric", "Authentication succeeded and decryption successful")
                            } else {
                                resultTextView.text = "Không tìm thấy file được mã hóa"
                                Log.d("Biometric", "File not found")
                            }
                        } catch (e: Exception) {
                            resultTextView.text = "Lỗi giải mã: ${e.message}"
                            Log.e("Biometric", "Decryption error", e)
                        }
                    } else {
                        resultTextView.text = "Lỗi: CryptoObject không có Cipher"
                        Log.e("Biometric", "Cipher is null")
                    }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    resultTextView.text = "Xác thực thất bại"
                    Log.d("Biometric", "Authentication failed")
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    resultTextView.text = "Lỗi xác thực: $errString ($errorCode)"
                    Log.e("Biometric", "Authentication error: $errString ($errorCode)")
                }
            }
        )
    }

    private fun startBiometricAuthentication() {
        try {
            // Get the decryption cipher from CryptoManager
            val decryptionCipher = cryptoManager.getDecryptCipher()

            // Create the prompt info
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Xác thực sinh trắc học")
                .setSubtitle("Quét vân tay để truy cập dữ liệu mã hóa")
                .setDescription("Sử dụng vân tay của bạn để giải mã dữ liệu bảo mật")
                .setNegativeButtonText("Hủy")
                .build()

            // Start authentication with the cipher in the CryptoObject
            biometricPrompt.authenticate(
                promptInfo,
                BiometricPrompt.CryptoObject(decryptionCipher)
            )

            Log.d("Biometric", "Authentication started")
        } catch (e: Exception) {
            e.printStackTrace()
            resultTextView.text = "Lỗi khởi tạo xác thực: ${e.message}"
            Log.e("Biometric", "Error initializing authentication", e)
        }
    }
}