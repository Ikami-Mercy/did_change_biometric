package com.example.did_change_authlocal

import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException

import android.security.keystore.KeyProperties
import androidx.annotation.NonNull
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricPrompt
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.security.InvalidKeyException
import java.security.Key
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import java.util.concurrent.Executors

/** DidChangeAuthlocalPlugin */
class DidChangeAuthlocalPlugin : FlutterPlugin, MethodCallHandler {
    /// The MethodChannel that will the communication between Flutter and native Android
    ///
    /// This local reference serves to register the plugin with the Flutter Engine and unregister it
    /// when the Flutter Engine is detached from the Activity
    private lateinit var channel: MethodChannel
    private var keyStore: KeyStore? = null
    private val KEY_NAME = "did_change_authlocal"
    private var biometricPrompt: BiometricPrompt? = null

    // Keystore binder calls can block for seconds on low-end devices; keep them off the main thread.
    private val keystoreExecutor = Executors.newSingleThreadExecutor()
    private val mainThreadHandler = Handler(Looper.getMainLooper())


    override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(
            flutterPluginBinding.binaryMessenger,
            "did_change_authlocal"
        )
        channel.setMethodCallHandler(this)
    }

    @RequiresApi(Build.VERSION_CODES.N)
    override fun onMethodCall(
        @NonNull call: MethodCall,
        @NonNull result: Result
    ) {
        if (call.method == "check") {
            val mainThreadResult = MainThreadResult(result, mainThreadHandler)
            keystoreExecutor.execute {
                try {
                    settingFingerPrint(mainThreadResult)
                } catch (e: Exception) {
                    // Same reply Flutter sends for an exception thrown on the platform thread.
                    Log.e("DidChangeAuthlocal", "check failed", e)
                    mainThreadResult.error("error", e.message, null)
                }
            }
        } else {
            result.notImplemented()
        }
    }

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private fun settingFingerPrint(result: Result) {
        val cipher: Cipher = getCipher()
        val secretKey: SecretKey = getSecretKey()

        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            result.success("biometric_valid")

        } catch (e: KeyPermanentlyInvalidatedException) {
            result.error(
                "biometric_did_change",
                "Yes your fingerprint has changed, please login to activate again",
                e.toString()
            )

        } catch (e: InvalidKeyException) {
            e.printStackTrace()
            result.error("biometric_invalid", "Invalid biometric", e.toString())
        }
        //Title require
        val promptInfo =
            BiometricPrompt.PromptInfo.Builder().setTitle("Biometric")
                .setDescription("Check Biometric").setNegativeButtonText("OK")
                .build()

        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            biometricPrompt?.authenticate(
                promptInfo,
                BiometricPrompt.CryptoObject(cipher)
            )
        } catch (e: KeyPermanentlyInvalidatedException) {
            keyStore?.deleteEntry(KEY_NAME)
            if (getCurrentKey(KEY_NAME) == null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    generateSecretKey(
                        KeyGenParameterSpec.Builder(
                            KEY_NAME,
                            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                        ).apply {
                            setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                            setUserAuthenticationRequired(true)
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                                setInvalidatedByBiometricEnrollment(true) // Invalidate the keys if the user has registered a new biometric
                            }
                        }.build()
                    )
                }
            }
        }
    }

    fun getCurrentKey(keyName: String): Key? {
        keyStore?.load(null)
        return keyStore?.getKey(keyName, null)
    }

    @RequiresApi(Build.VERSION_CODES.N)
    fun getSecretKey(): SecretKey {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore")
        } catch (e: Exception) {
            e.printStackTrace()
        }
        var keyGenerator: KeyGenerator? = null
        try {
            keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            )
        } catch (e: Exception) {
            e.printStackTrace()
        }
        try {
            if (getCurrentKey(KEY_NAME) == null) {
                keyGenerator!!.init(
                    KeyGenParameterSpec.Builder(
                        KEY_NAME,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                    ).apply {
                        setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        setUserAuthenticationRequired(true)
                        setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                            setInvalidatedByBiometricEnrollment(true)
                        }
                    }.build()
                )
                keyGenerator.generateKey()
            }

        } catch (e: Exception) {
            e.printStackTrace()
        }
        return keyStore?.getKey(KEY_NAME, null) as SecretKey
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun getCipher(): Cipher {
        return Cipher.getInstance(
            KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7
        )
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun generateSecretKey(keyGenParameterSpec: KeyGenParameterSpec) {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    }
}

private class MainThreadResult(
    private val result: Result,
    private val handler: Handler
) : Result {
    private var replied = false

    override fun success(value: Any?) = reply { result.success(value) }

    override fun error(code: String, message: String?, details: Any?) =
        reply { result.error(code, message, details) }

    override fun notImplemented() = reply { result.notImplemented() }

    private fun reply(send: () -> Unit) {
        if (replied) return
        replied = true
        handler.post(send)
    }
}
