package com.accidentalproductions.secretmessage

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class MainActivity : AppCompatActivity() {

    private lateinit var inputMessage: EditText
    private lateinit var encryptButton: Button
    private lateinit var encryptedMessage: TextView
    private lateinit var encryptionKey: TextView
    private lateinit var shareButton: Button
    private lateinit var encryptedMessageInput: EditText
    private lateinit var decryptionKeyInput: EditText
    private lateinit var decryptButton: Button
    private lateinit var decryptedMessageTextView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Set the styled app title with pale blue color
        val actionBar = supportActionBar
        actionBar?.title = resources.getString(R.string.app_name_pale_blue)

        inputMessage = findViewById(R.id.inputMessage)
        encryptButton = findViewById(R.id.encryptButton)
        encryptedMessage = findViewById(R.id.encryptedMessage)
        encryptionKey = findViewById(R.id.encryptionKey)
        shareButton = findViewById(R.id.shareButton)
        encryptedMessageInput = findViewById(R.id.encryptedMessageInput)
        decryptionKeyInput = findViewById(R.id.decryptionKeyInput)
        decryptButton = findViewById(R.id.decryptButton)
        decryptedMessageTextView = findViewById(R.id.decryptedMessageTextView)

        encryptButton.setOnClickListener {
            val message = inputMessage.text.toString()
            val key = generateRandomKey()

            val encryptedText = encrypt(message, key)
            encryptedMessage.text = getString(R.string.encrypted_message_label, encryptedText)

            val keyText = bytesToHex(key.encoded)
            encryptionKey.text = getString(R.string.encryption_key_label, keyText)

            // Allow copying encrypted message and key to clipboard
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Encrypted Data", "Encrypted Message: $encryptedText\n\nDecryption Key: $keyText")
            clipboard.setPrimaryClip(clip)
        }


        shareButton.setOnClickListener {
            val message = encryptedMessage.text.toString()
            val key = encryptionKey.text.toString()

            val shareText = "\n$message\n\n$key"

            val sendIntent: Intent = Intent().apply {
                action = Intent.ACTION_SEND
                putExtra(Intent.EXTRA_TEXT, shareText)
                type = "text/plain"
            }

            val shareIntent = Intent.createChooser(sendIntent, null)
            startActivity(shareIntent)
        }

        decryptButton.setOnClickListener {
            val encryptedMessage = encryptedMessageInput.text.toString()
            val decryptionKey = decryptionKeyInput.text.toString()

            val decryptedMessage = decrypt(encryptedMessage, decryptionKey)
            decryptedMessageTextView.text = getString(R.string.decrypted_message_label, decryptedMessage)
        }
    }


    private fun generateRandomKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)
        return keyGenerator.generateKey()
    }

    private fun encrypt(input: String, key: SecretKey): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val encryptedBytes = cipher.doFinal(input.toByteArray())
        return bytesToHex(iv) + bytesToHex(encryptedBytes)
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            hexChars[i * 2] = "0123456789ABCDEF"[v ushr 4]
            hexChars[i * 2 + 1] = "0123456789ABCDEF"[v and 0x0F]
        }
        return String(hexChars)
    }

    private fun decrypt(encryptedText: String, key: String): String {
        val keyBytes = hexToBytes(key)
        val secretKey = SecretKeySpec(keyBytes, "AES")

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val iv = encryptedText.substring(0, 32) // Extract IV from the encryptedText
        val encryptedData = encryptedText.substring(32)

        val ivBytes = hexToBytes(iv)
        val ivParameterSpec = IvParameterSpec(ivBytes)

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec)

        val decryptedBytes = cipher.doFinal(hexToBytes(encryptedData))
        return String(decryptedBytes)
    }

    private fun hexToBytes(hexString: String): ByteArray {
        val len = hexString.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            val hexByte = hexString.substring(i, i + 2)
            data[i / 2] = hexByte.toInt(16).toByte()
            i += 2
        }
        return data
    }

}
