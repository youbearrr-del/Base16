package com.dulz.system.installer

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

data class Release(val applicationName:String,val versionName:String,val versionCode:Int,val channel:String,val checksum:String,val mandatory:Boolean)
class ApiException(message:String): Exception(message)
class ApiClient(private val baseUrl:String) {
    private suspend fun request(path:String, method:String="GET", token:String?=null, payload:JSONObject?=null):JSONObject = withContext(Dispatchers.IO) {
        val c=(URL("$baseUrl$path").openConnection() as HttpURLConnection).apply { requestMethod=method; setRequestProperty("Accept","application/json"); if(token!=null)setRequestProperty("Authorization","Bearer $token"); if(payload!=null){doOutput=true;setRequestProperty("Content-Type","application/json");outputStream.use{it.write(payload.toString().toByteArray())}} }
        val raw=(if(c.responseCode in 200..299)c.inputStream else c.errorStream).bufferedReader().use{it.readText()}; val json=JSONObject(raw)
        if(c.responseCode !in 200..299) throw ApiException(json.optString("error","Request failed")); json
    }
    suspend fun login(username:String,password:String):String=request("/auth/login","POST",payload=JSONObject().put("username",username).put("password",password)).getString("token")
    suspend fun session(token:String):String=request("/client/session",token=token).getJSONObject("user").getString("username")
    suspend fun releases(token:String):List<Release>{val arr:JSONArray=request("/client/releases",token=token).getJSONArray("releases");return List(arr.length()){i->arr.getJSONObject(i).let{Release(it.getString("application_name"),it.getString("version_name"),it.getInt("version_code"),it.getString("channel"),it.getString("sha256"),it.optInt("mandatory")==1)}}}
}
