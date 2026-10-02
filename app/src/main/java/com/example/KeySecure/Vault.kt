package com.example.KeySecure

import android.content.Context
import android.util.Base64
import androidx.compose.runtime.mutableStateListOf
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import javax.crypto.Cipher

class Entry(val site: String, val user: String, val pass: String)

/**
 * vaultKey = PBKDF2(texto-chave). Os dados são cifrados com vaultKey (AES-GCM).
 * A vaultKey fica guardada "embrulhada" de duas formas: pela chave derivada do PIN
 * e pela chave do Keystore (biometria). Nada em texto puro vai para o disco.
 */
class Vault(ctx: Context) {
    private val f = File(ctx.filesDir, "vault.json")
    private var key: ByteArray? = null
    val entries = mutableStateListOf<Entry>()

    private fun b(s: String) = Base64.decode(s, Base64.NO_WRAP)
    private fun s(x: ByteArray) = Base64.encodeToString(x, Base64.NO_WRAP)
    private fun meta() = JSONObject(f.readText())

    fun exists() = f.exists()
    fun bioEnabled() = exists() && meta().has("wb")

    fun create(pin: String, phrase: String) {
        val sp = Crypto.rand(16); val sn = Crypto.rand(16)
        val k = Crypto.derive(phrase, sp); key = k
        f.writeText(JSONObject().put("sn", s(sn))
            .put("wp", s(Crypto.encrypt(Crypto.derive(pin, sn), k))).toString())
        save()
    }

    fun unlockPin(pin: String): Boolean = try {
        val m = meta()
        key = Crypto.decrypt(Crypto.derive(pin, b(m.getString("sn"))), b(m.getString("wp")))
        load(); true
    } catch (e: Exception) { key = null; false }

    fun bioIv(): ByteArray = b(meta().getString("wbi"))

    fun enableBio(c: Cipher) {           // cipher em ENCRYPT_MODE já autenticado
        val wrapped = c.doFinal(key!!)
        f.writeText(meta().put("wb", s(wrapped)).put("wbi", s(c.iv)).toString())
    }

    fun unlockBio(c: Cipher): Boolean = try {
        key = c.doFinal(b(meta().getString("wb"))); load(); true
    } catch (e: Exception) { key = null; false }

    fun add(e: Entry) { entries.add(e); save() }
    fun remove(e: Entry) { entries.remove(e); save() }
    fun lock() { key = null; entries.clear() }

    private fun save() {
        val arr = JSONArray()
        entries.forEach { arr.put(JSONObject().put("s", it.site).put("u", it.user).put("p", it.pass)) }
        val blob = Crypto.encrypt(key!!, arr.toString().toByteArray())
        f.writeText(meta().put("d", s(blob)).toString())
    }

    private fun load() {
        entries.clear()
        val arr = JSONArray(String(Crypto.decrypt(key!!, b(meta().getString("d")))))
        for (i in 0 until arr.length()) arr.getJSONObject(i).let {
            entries.add(Entry(it.getString("s"), it.getString("u"), it.getString("p")))
        }
    }
}
