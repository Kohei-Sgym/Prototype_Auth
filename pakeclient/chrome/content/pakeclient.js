	//プロトタイプ
Components.utils.import("resource://services-sync/constants.js");
Components.utils.import("resource://services-sync/rest.js");
Components.utils.import("resource://services-sync/util.js");


const JPAKE_SIGNERID_SENDER   = "sender";//送信
const JPAKE_SIGNERID_RECEIVER = "receiver";//受信
const JPAKE_VERIFY_VALUE      = "0123456789ABCDEF";


	//header・request・resqonse検知用
	//未実装
/*
StreamCatchtest = function(){
	
	this.headers = new Array();
	this.observers = new Array(); //Observers
}
StreamCatchtest.prototype = {
oHttp:null,
observe: function(aSubject,aTopic,aData){
		//Cookieデータがリクエストに読み込まれた時，リクエスト送信前に動作
	if(aTopic == 'http-on-modify-request'){
		aSubject.QueryInterface(Components.interfaces.nsIHttpChannel);
		this.onModifyRequest(aSubject);
			//レスポンスが受け取られた時，Cookieが処理される前に動作
	}else if(aTopic == 'http-on-examine-response'){
		aSubject.QueryInterface(Components.interfaces.nsIHttpChannel);
		this.onExamineResponse(aSubject);
	}
},
		//リクエスト時に検知
onModifyRequest: function(oHttp){
	
},

onExamineResponse: function(oHttp){
	
	var name = typeof(oHttp);
	
	var CatchResponse = new StreamCatchResponse(oHttp);
	
	var response = CatchResponse.visitResponse();
		//var header = oHttp.getResponseHeader("WWW-Authentication");
},
QueryInterface: function(iid) {
    if (!iid.equals(Components.interfaces.nsISupports) &&
        !iid.equals(Components.interfaces.nsIHttpNotify) &&
        //!iid.equals(Components.interfaces.nsIClassInfo) &&
        //!iid.equals(Components.interfaces.nsISecurityCheckedComponent) &&
        //!iid.equals(Components.interfaces.nsIWeakReference) &&
        !iid.equals(Components.interfaces.nsIHttpNotify) &&
        !iid.equals(Components.interfaces.nsIObserver)) {
			//dump("LiveHTTPHeaders: QI unknown iid: " + iid + "\n");
		throw Components.results.NS_ERROR_NO_INTERFACE;
	}
	return this;
}
};
 

StreamCatchResponse = function(oHttp){
	this.oHttp = oHttp;
	this.headers = new Array();
}
StreamCatchResponse.prototype = {
oHttp:null,
headers:null,
	
visitHeader: function(name, value){
	this.headers[name] = value;
},
visitResponse: function(){
	
	this.headers = new Array();
		//alert(typeof(oHttp));
	this.headers["RESPONSE"] = "TESTHEAD " + this.oHttp;
	
	this.oHttp.visitResponseHeaders(this);
	return this.headers;
}
};
*/

function pakeClient(){
	
	this._my_signerid = JPAKE_SIGNERID_SENDER;
	this._their_signerid = JPAKE_SIGNERID_RECEIVER;
	var _username;
	var _userpath;
	var _servletUrl;
	var _channel;
	
		//JPAKEのインスタンス生成
	this._jpake = Components.classes["@mozilla.org/services-crypto/sync-jpake;1"].createInstance(Components.interfaces.nsISyncJPAKE);
	
	
		//オブザーバの追加・通知
	/*
	var observerService = Components.classes["@mozilla.org/observer-service;1"].getService(Components.interfaces.nsIObserverService);
	
	
		//検知用のオブジェクト生成
	var examineHeader = new StreamCatchtest();
	
		//observerSeに登録？
	try{
		observerService.addObserver(examineHeader,"http-on-modify-request",false);
		observerService.addObserver(examineHeader,"http-on-examine-response",false);
	}catch(err){
	}
	*/
}	
		//prototype
pakeClient.prototype = {
	
			//文字のバイト数を取得
	getByte: function getByte(text){
		count = 0;
		for (i=0; i<text.length; i++){
			n = escape(text.charAt(i));
			if (n.length < 4) count++; else count+=2;
		}
		return count;
	},
asyncChain: function asyncChain() {
	let argument = arguments.length;
    let funcs = Array.slice(arguments);
	let thisObj = this;
    return function callback() {
		if (funcs.length) {
				//alert("thisObj = " + thisObj);
			let args = Array.slice(arguments).concat(callback);
			let f = funcs.shift();
			f.apply(thisObj, args);
		}
    };
},
	
		//ユーザ情報取得
wizard: function(){
		//window.openDialog("chrome://test/content/testconfig.xul","wizard","chrome,centerscreen,modal,resizable,alwaysRaised,close=no");
	var win = window.openDialog("chrome://pakeClient/content/config.xul","wizard","chrome,centerscreen,modal,resizable,alwaysRaised");
		//入力無しならエラー処理(予定)
},
	
authentication: function(){
	
		//逐次実行
	this.asyncChain(this.stepOne,
					this.postStepOne,
					this.stepTwo,
					this.postStepTwo,
					this.stepFinal,
					this.computeKeyVerification,
					this.postStepFinal,
					this.decryptData)();
	
},

	
		//stepOne
stepOne: function(callback){
	
	let gx1 = {};
    let gv1 = {};
    let r1 = {};
    let gx2 = {};
    let gv2 = {};
    let r2 = {};	
	//C++
	//nsSyncJPAKE::Round1
	try{
	this._jpake.round1(this._my_signerid, gx1, gv1, r1, gx2, gv2, r2);
	}catch(ex){
	return false;
	}
	/*
	 送信用データ生成
	 type: sender
	 payload: one: gx1,gx2,gv1,gv2,r1,r2,id
	 */	
	let one = {gx1: gx1.value,
	gx2:gx2.value,
	zkp_x1: {gr: gv1.value, b: r1.value, id: this._my_signerid},
	zkp_x2: {gr: gv2.value, b: r2.value, id: this._my_signerid},
	user:this._username
	};
		//alert("stepone");
	this._outgoing = {type: this._my_signerid + "1", payload: one};
	callback();
},

		//stepTwo
stepTwo: function(callback){
	//受信データ取得
	let step1 = this._incoming.payload;
	
	if (!step1 || !step1.zkp_x1 || step1.zkp_x1.id != this._their_signerid
        || !step1.zkp_x2 || step1.zkp_x2.id != this._their_signerid) {
			//処理の停止
		alert("処理中止");
		return;
    }
	
	
	let A = {};
	let gvA = {};
	let rA = {};
	
	this._pakeSecret = this._userpath;
		//C++ nsSyncJPAKE::Round2
	try{
	this._jpake.round2(this._their_signerid,this._pakeSecret,
					   step1.gx1,step1.zkp_x1.gr,step1.zkp_x1.b,
					   step1.gx2,step1.zkp_x2.gr,step1.zkp_x2.b,
					   A,gvA,rA);
	}catch(ex){
		alert(ex);
		return false;
	}
		//送信データ生成
	let two = {A:A.value,
		zkp_A:{gr:gvA.value,b:rA.value,id:this._my_signerid},
		user:this._username};
	this._outgoing = null;
		//送信用データ
	this._outgoing = {type: this._my_signerid + "2",payload: two}
	
	callback();
	
},
	
		//stepFinal
stepFinal: function(callback){
		//エラー処理
		//エラーなら処理中止
		//送信されたBとその署名
	let step2 = this._incoming.payload;
		//alert("final");
		//エラー処理
	if (!step2 || !step2.zkp_A || step2.zkp_A.id != this._their_signerid) {
			alert("処理中止");
		return false;
    }
	let aes256Key = {};
    let hmac256Key = {};
	
		//final
	try{
	this._jpake.final(step2.A, step2.zkp_A.gr, step2.zkp_A.b, HMAC_INPUT,
					  aes256Key, hmac256Key);
	}
	catch(ex){
		alert(ex);
		return false;
	}
	
	this._crypto_key = aes256Key.value;
	let hmac_key = Utils.makeHMACKey(Utils.safeAtoB(hmac256Key.value));
	this._hmac_hasher = Utils.makeHMACHasher(Components.interfaces.nsICryptoHMAC.SHA256, hmac_key);
	
	callback();
},

computeKeyVerification: function computeKeyVerification(callback){
	let iv, ciphertext;
	
	try{
		iv = Svc.Crypto.generateRandomIV();
		ciphertext = Svc.Crypto.encrypt(JPAKE_VERIFY_VALUE,this._crypto_key,iv);
	}catch(ex){
		alert(ex);
	}
	
	this._outgoing = {type:this._my_signerid + "3",payload:{cip:ciphertext,IV:iv}};
	
	callback();
},
decryptData: function decryptData(callback){
	let step3 = this._incoming.payload;
	
	let check = null;
	try{
		let hmac = Utils.bytesAsHex(Utils.digestUTF8(step3.cip,this._hmac_hasher));
		if(hmac != step3.hmac){
				//処理中止予定
		}
	}catch(ex){
		alert(ex);
	}
	let cleartext;
	try{
		cleartext = Svc.Crypto.decrypt(step3.cip,this._crypto_key,step3.IV);
	}catch(ex){
		alert(ex);
	}
	try{
		this._newData = cleartext;
	}catch(ex){
		alert(ex);
	}
		//エラー無し = 認証できたという事でブラウザのリロード
	window.opener.gBrowser.selectedBrowser.contentDocument.location.reload();
},

		//post(1回目)
postStepOne: function(callback){
	
		//JSONObject
	data = JSON.stringify(this._outgoing);
	var request = new XMLHttpRequest();
	request.open("POST","https://idp.example.com/idp/Authn/PAKE",false);
	
		//JPAKEの処理用のHeader追加(予定)
	request.setRequestHeader("Content-type","application/json;text/utf-8");
	request.setRequestHeader("Round","Round1");
	request.setRequestHeader("Auth-PAKELogin","PAKEAuth");
	
	request.send(data)

		//response
	this._servletUrl = request.getResponseHeader("Location");
		//alert("step1 = " + this._servletUrl);
	this._incoming = JSON.parse(request.responseText);
	
	callback();

},
		//post(2回目)
postStepTwo: function(callback){
	var request = new XMLHttpRequest();
	
	data = JSON.stringify(this._outgoing);
	if(this._servletUrl != null){
		request.open("POST",this._servletUrl,false);
	}else{
		request.open("POST","https://idp.example.com/idp/Authn/UsernamePassword" + this._their_signerid + "2",false);
	}
	request.setRequestHeader("Content-type","application/json;text/utf-8");
	request.setRequestHeader("Round","Round2");
	request.setRequestHeader("Auth-PAKELogin","PAKEAuth");
	
	request.send(data);
	
	this._incoming = null;
		//レスポンス取得
	this._incoming = JSON.parse(request.responseText);
	
	callback();
	
},
	
		//3回目
postStepFinal: function(callback){

	var request = new XMLHttpRequest();
	this._incoming = null;
	
	data = JSON.stringify(this._outgoing);
	
	request.open("POST",this._servletUrl,false);
	request.setRequestHeader("Content-type","application/json;text/utf-8");
	request.setRequestHeader("Round","Final");
	request.setRequestHeader("Auth-PAKELogin","PAKEAuth");
	request.send(data);
	this._incoming = null;
	this._incoming = JSON.parse(request.responseText);
	callback();
},
	//ユーザ入力データ取得
start: function(){
	//wizardで入力された数値を取得する.
	this._username = document.getElementById("userID").value;
	this._userpath = document.getElementById("password").value;
	
	//pakeによる認証処理を実行
	this.authentication();
},
	
		//終了
abort: function(){
	
	//セッションに記録された情報を失敗した場合消去するためのメソッドが必要である
	//でないと，また続いて認証を行うことが出来ない．
	this._finished = true;
    let self = this;
	return false;
},
};
var Client = new pakeClient;

window.addEventListener("DOMContentLoaded",function(e){loadContent(e);},false);

function loadContent(aEvent){
	if(aEvent.originalTarget.location){
		var currentSelectTabUrl = gBrowser.selectedBrowser.contentDocument.location.href;
		var dOMContentLoadedUrl = aEvent.originalTarget.location.href;
		
		var testUrl = "https://idp.example.com/idp/Authn/UserPassword";
		
		if(dOMContentLoadedUrl == testUrl){
				//alert(dOMContentLoadedUrl);
				Client.wizard();
		}
	}
}


