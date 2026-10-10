package com.dulz.system.installer

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch

private val Orange=Color(0xFFFF6A31); private val Ink=Color(0xFF171520)
class InstallerViewModel:ViewModel(){private val api=ApiClient(BuildConfig.API_BASE_URL);var token by mutableStateOf<String?>(null);var username by mutableStateOf("");var releases by mutableStateOf<List<Release>>(emptyList());var error by mutableStateOf<String?>(null);var loading by mutableStateOf(false)
    fun login(user:String,pass:String)=viewModelScope.launch{loading=true;error=null;try{token=api.login(user,pass);username=api.session(token!!);releases=api.releases(token!!)}catch(e:Exception){token=null;error=e.message?:"Unable to sign in"}finally{loading=false}}
    fun refresh()=viewModelScope.launch{try{releases=api.releases(requireNotNull(token))}catch(e:Exception){error=e.message}}
    fun logout(){token=null;username="";releases=emptyList()}
}
class MainActivity:ComponentActivity(){override fun onCreate(savedInstanceState:Bundle?){super.onCreate(savedInstanceState);setContent{MaterialTheme(colorScheme=darkColorScheme(primary=Orange,surface=Ink,background=Ink)){val vm:InstallerViewModel=viewModel();Surface{if(vm.token==null)Login(vm)else Home(vm)}}}}}
@Composable fun Login(vm:InstallerViewModel){var user by remember{mutableStateOf("")};var pass by remember{mutableStateOf("")};Column(Modifier.fillMaxSize().background(Ink).padding(28.dp),verticalArrangement=Arrangement.Center){Text("Dulz",style=MaterialTheme.typography.displaySmall,fontWeight=FontWeight.Bold,color=Orange);Text("Apk DulzInstaller",style=MaterialTheme.typography.titleLarge);Spacer(Modifier.height(28.dp));OutlinedTextField(user,{user=it},label={Text("Username")},modifier=Modifier.fillMaxWidth());Spacer(Modifier.height(10.dp));OutlinedTextField(pass,{pass=it},label={Text("Password")},modifier=Modifier.fillMaxWidth());vm.error?.let{Text(it,color=MaterialTheme.colorScheme.error)};Spacer(Modifier.height(20.dp));Button({vm.login(user,pass)},enabled=!vm.loading,modifier=Modifier.fillMaxWidth()){Text(if(vm.loading)"Signing in…" else "Sign in")};Text("Development API: ${BuildConfig.API_BASE_URL}",style=MaterialTheme.typography.labelSmall,modifier=Modifier.padding(top=14.dp))}}
@Composable fun Home(vm:InstallerViewModel){Column(Modifier.fillMaxSize().background(Ink).padding(20.dp)){Row(Modifier.fillMaxWidth(),horizontalArrangement=Arrangement.SpaceBetween){Column{Text("Welcome, ${vm.username}",style=MaterialTheme.typography.titleLarge);Text("Available authorized releases")};TextButton({vm.logout()}){Text("Sign out")}};Button({vm.refresh()}){Text("Check updates")};Spacer(Modifier.height(12.dp));LazyColumn{items(vm.releases){r->Card(Modifier.fillMaxWidth().padding(vertical=6.dp)){Column(Modifier.padding(16.dp)){Text(r.applicationName,fontWeight=FontWeight.Bold);Text("${r.versionName} · build ${r.versionCode} · ${r.channel}");Text(if(r.mandatory)"Mandatory update" else "Optional update",color=Orange);Text("Checksum verified before install is enabled.",style=MaterialTheme.typography.labelSmall)}}}}}}
