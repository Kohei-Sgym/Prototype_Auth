package com.skym.shibboleth.idp.keyjuggling;

import java.io.*;
import java.util.*;
import java.math.BigInteger;
import java.nio.*;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import java.io.IOException;
import java.security.Principal;
import java.util.Set;
import net.sf.json.*;
import java.io.Reader;
import java.io.BufferedReader;
import org.apache.commons.codec.binary.Base64;

import java.security.*;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.*;
import java.security.spec.*;

import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;

	//Ldapアクセス用
import edu.vt.middleware.ldap.*;
import edu.vt.middleware.ldap.dsml.*;
import edu.vt.middleware.ldap.dsml.AbstractDsml;
import edu.vt.middleware.ldap.Ldap;
import edu.vt.middleware.ldap.SearchFilter;
import edu.vt.middleware.ldap.bean.LdapAttribute;
import edu.vt.middleware.ldap.bean.LdapAttributes;
import edu.vt.middleware.ldap.bean.LdapBeanProvider;
import edu.vt.middleware.ldap.pool.*;
import javax.naming.directory.SearchResult;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.Attribute;

import com.skym.shibboleth.idp.keyjuggling.PasswordKeyExchangeLoginServlet;

public class KeyJugglingServlet extends HttpServlet{
		//uid
	private static final long serialVersionUID = 1L;
	private static final int MaxLength = 384;
	private static final int MinLength = 33;
	static private final BigInteger p = new BigInteger("90066455B5CFC38F9CAA4A48B4281F292C260FEEF01FD61037E56258A7795A1C7AD46076982CE6BB956936C6AB4DCFE05E6784586940CA544B9B2140E1EB523F009D20A7E7880E4E5BFA690F1B9004A27811CD9904AF70420EEFD6EA11EF7DA129F58835FF56B89FAA637BC9AC2EFAAB903402229F491D8D3485261CD068699B6BA58A1DDBBEF6DB51E8FE34E8A78E542D7BA351C21EA8D8F1D29F5D5D15939487E27F4416B0CA632C59EFD1B1EB66511A5A0FBF615B766C5862D0BD8A3FE7A0E0DA0FB2FE1FCB19E8F9996A8EA0FCCDE538175238FC8B0EE6F29AF7F642773EBE8CD5402415A01451A840476B2FCEB0E388D30D4B376C37FE401C2A2C2F941DAD179C540C1C8CE030D460C4D983BE9AB0B20F69144C1AE13F9383EA1C08504FB0BF321503EFE43488310DD8DC77EC5B8349B8BFE97C2C560EA878DE87C11E3D597F1FEA742D73EEC7F37BE43949EF1A0D15C3F3E3FC0A8335617055AC91328EC22B50FC15B941D3D1624CD88BC25F3E941FDDC6200689581BFEC416B4B2CB73",16);
	static private final BigInteger q = new BigInteger("CFA0478A54717B08CE64805B76E5B14249A77A4838469DF7F7DC987EFCCFB11D",16);
	static private final BigInteger g = new BigInteger("5E5CBA992E0A680D885EB903AEA78E4A45A469103D448EDE3B7ACCC54D521E37F84A4BDD5B06B0970CC2D2BBB715F7B82846F9A0C393914C792E6A923E2117AB805276A975AADB5261D91673EA9AAFFEECBFA6183DFCB5D3B7332AA19275AFA1F8EC0B60FB6F66CC23AE4870791D5982AAD1AA9485FD8F4A60126FEB2CF05DB8A7F0F09B3397F3937F2E90B9E5B9C9B6EFEF642BC48351C46FB171B9BFA9EF17A961CE96C7E7A7CC3D3D03DFAD1078BA21DA425198F07D2481622BCE45969D9C4D6063D72AB7A0F08B2F49A7CC6AF335E08C4720E31476B67299E231F8BD90B39AC3AE3BE0C6B6CACEF8289A2E2873D58E51E029CAFBD55E6841489AB66B5B4B9BA6E2F784660896AFF387D92844CCB8B69475496DE19DA2E58259B090489AC8E62363CDF82CFD8EF2A427ABCD65750B506F56DDE3B988567A88126B914D7828E2B63A6D7ED0747EC59E0E0A23CE7D8A74C1D2C2A7AFB6A29799620F00E11C33787F7DED3B30E1A22D09F1FBDA1ABBBFBF25CAE05A13F812E34563F99410E73B",16);
	
	static private final String message = "receiver";
	
	
	private final Logger log = LoggerFactory.getLogger(KeyJugglingServlet.class);
		//JSONObject
		//JSONObject jObject;
	
	public void init(ServletConfig config){
		try{
		super.init(config);
		}catch(ServletException e){
		}
	}
	
	protected void service(HttpServletRequest request, HttpServletResponse response){
		
		JSONObject obj = null;
		String payload = "";
		String round = null;
		
		HashMap<String,String> payloadList;
			//セッション取得
		HttpSession session = request.getSession();
			//response encode
		response.setContentType("text/html; charset=UTF-8");
		//やり取りの確認
		if(session.getAttribute("Round") == null){
			session.setAttribute("Round","Round1");
			round = (String)session.getAttribute("Round");
		}else{
			round = (String)session.getAttribute("Round");
		}
		
		try{
			BufferedReader str = new BufferedReader(request.getReader());
			payload = str.readLine();
			str.close();
		}catch(IOException ex){
			
		}
			//JSON形式の文字列payloadを要素ごとに分けてlistに記録する
			//セッションにリストが記録されているのか確認
		if(session.getAttribute("payload") != null){
				//前回のlistを持ってくる
			payloadList = (HashMap<String,String>)session.getAttribute("payload");
		}else{
				//新しくhashmapを作る
			payloadList = new HashMap<String,String>(24);
		}
			//Listにリクエストのbody部分を追加
		JSONParse(request,payload,payloadList,round);
		
			//応答先
		response.setHeader("Location","https://idp.example.com/idp/Authn/PAKE");
		
		if(round.equals("Round1")){
				//レスポンス作成(G(X3) & G(X4))
			obj = setRoundOne(request,response,payloadList);
				//次のラウンドを記録
			session.setAttribute("Round","Round2");
				//log.info("session = " + (String)session.getAttribute("Round"));
		}
		else if(round.equals("Round2")){
				
			try{
				//レスポンス作成(A)
			obj = setRoundTwo(request,response,payloadList,payload);
			session.setAttribute("Round","Final");
			}catch(Exception e){
				log.error("step two error",e);
			}
		}
		else if(round.equals("Final")){
				//レスポンス作成
			obj = setRoundFinal(request,response,payloadList);
			if(obj != null){
					//認証へ遷移のための記録
				session.setAttribute("PAKEAuth","OK");
			}
		}
		
			//HashMap記録
		session.setAttribute("payload",payloadList);
		try{
			request.setCharacterEncoding("UTF-8");
			response.setHeader("Content-type","application/json");
				//応答
			PrintWriter out = response.getWriter();
			out.print(obj);
			out.flush();
		}catch(Exception e){
			log.error("response error ",e);
		}
		
		
	}
		//round1
	protected JSONObject setRoundOne(HttpServletRequest request, HttpServletResponse response,HashMap output){
		
		/*
		*検証式はこの段階で行うか，HashMapに記録する前に行うか検討中
		 */
		
		BigInteger X3 = randomNumber();
		BigInteger X4 = randomNumber();
		BigInteger GX1 = generateGX(this.g,this.p,X3);
		BigInteger GX2 = generateGX(this.g,this.p,X4);
			//記録用リスト
			//HashMapに記録する
		output.put("X3",byte2HexString(X3.toByteArray()));
		output.put("X4",byte2HexString(X4.toByteArray()));
		output.put("GX3",byte2HexString(GX1.toByteArray()));
		output.put("GX4",byte2HexString(GX2.toByteArray()));
		
		String[] ZKP1 = generateZKP(this.g,this.p,this.q,X3,GX1,this.message);
		String[] ZKP2 = generateZKP(this.g,this.p,this.q,X4,GX2,this.message);
		
			//レスポンス作成
		JSONObject obj_ZKP1 = new JSONObject();
		obj_ZKP1.put("gr",ZKP1[0]);
		obj_ZKP1.put("b", ZKP1[1]);
		obj_ZKP1.put("id",message);
		
		JSONObject obj_ZKP2 = new JSONObject();
		obj_ZKP2.put("gr",ZKP2[0]);
		obj_ZKP2.put("b", ZKP2[1]);
		obj_ZKP2.put("id",message);	
		
		JSONObject obj_Payload = new JSONObject();
		obj_Payload.put("gx1",byte2HexString(GX1.toByteArray()));
		obj_Payload.put("gx2",byte2HexString(GX2.toByteArray()));
		obj_Payload.put("zkp_x1", obj_ZKP1);
		obj_Payload.put("zkp_x2", obj_ZKP2);
		
		JSONObject obj = new JSONObject();
		obj.put("type","receiver1");
		obj.put("payload",obj_Payload);
		
		return obj;
	}
		//round2
	protected JSONObject setRoundTwo(HttpServletRequest request, HttpServletResponse response,HashMap output, String payload)throws NamingException {
			//jObject = null;
			//keyExchangeValue.setValue(request,round);
		JSONObject obj = new JSONObject();
		JSONObject sender = new JSONObject();
		
		sender = JSONObject.fromObject(payload);
		HttpSession session = request.getSession();
		//HashMapからX4を取得
		BigInteger X4 = new BigInteger((String)output.get("X4"),16);
		/*
		 *未実装
		 *ldapサーバ側から記録されたパスワードを取得
		 */
		//試験的にtestSearchを呼び出す
		log.info("testlog log");
		String testPass = testSearch((String)output.get("userID"));
        
			//パスワードのバイト配列を取得
		String pass = "userpassword";
		BigInteger Secret = new BigInteger(1,pass.getBytes());
		
		BigInteger X4S = X4.multiply(Secret);
		BigInteger X4S_modq = X4S.mod(this.q);
		
		BigInteger GX1 = new BigInteger((String)output.get("GX1"),16);
		BigInteger GX2 = new BigInteger((String)output.get("GX2"),16);
		BigInteger GX3 = new BigInteger((String)output.get("GX3"),16);
		BigInteger GX4 = new BigInteger((String)output.get("GX4"),16);
		
			//サーバ側
		BigInteger serverBase = GX3.multiply(GX1).multiply(GX2).mod(this.p);
			//クライアント側
		BigInteger cliantBase = GX1.multiply(GX3).multiply(GX4).mod(this.p);
		
		BigInteger ZKPA0 = null;
		BigInteger ZKPA1 = null;
		
		String num0 = sender.optJSONObject("payload").getJSONObject("zkp_A").optString("gr");
		ZKPA0 = new BigInteger(num0,16);
		String num1 = sender.optJSONObject("payload").getJSONObject("zkp_A").optString("b");
		ZKPA1 = new BigInteger(num1,16);
		
		BigInteger[] senderZKPA_int = {ZKPA0,ZKPA1};
		
		if(verifydZKP(cliantBase,this.p,this.q,new BigInteger((String)output.get("A"),16),senderZKPA_int,(String)output.get("message")) == true){
				
		BigInteger B = serverBase.modPow(X4S_modq,this.p);
		
		String[] ZKPB = generateZKP(serverBase,this.p,this.q,X4S_modq,B,this.message);
		
			//step2のList作成
		output.put("B",byte2HexString(B.toByteArray()));
		
		JSONObject obj_ZKPB = new JSONObject();
		obj_ZKPB.put("gr",ZKPB[0]);
		obj_ZKPB.put("b",ZKPB[1]);
		obj_ZKPB.put("id",message);
		
		JSONObject obj_Payload = new JSONObject();
		obj_Payload.put("A",byte2HexString(B.toByteArray()));
		obj_Payload.put("zkp_A",obj_ZKPB);
			
			
		obj.put("type","receiver2");
		obj.put("payload",obj_Payload);
			
		}else{
		}
		return obj;
	}
		//final
	protected JSONObject setRoundFinal(HttpServletRequest request, HttpServletResponse response,HashMap output){
		JSONObject obj = null;
		
		BigInteger X4 = new BigInteger((String)output.get("X4"),16);
		BigInteger GX2 = new BigInteger((String)output.get("GX2"),16);
		BigInteger A = new BigInteger((String)output.get("A"),16);
		
		/*
		 *計算のやり直しを行う必要あり
		 *もしくは，step2の段階で，計算してsessionに記録する形を取る方向に
		 */
		
		String pass = "userpassword";
		BigInteger Secret = new BigInteger(1,pass.getBytes());
		BigInteger X4S = X4.multiply(Secret);
		
		BigInteger X4S_modq = this.q.subtract(X4S);
		
		BigInteger Key = GX2.modPow(X4S_modq,this.p).multiply(A).modPow(X4,this.p);
		
		obj = SymKey(Key,(String)output.get("cip"),(String)output.get("IV"));
		
		return obj;
	}
		//randomNumber
	private BigInteger randomNumber(){
		BigInteger X = null;
		
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[160];
		
		random.nextBytes(bytes);
		
		BigInteger W = new BigInteger(1,bytes);
		
		X = W.mod(this.q);
		
		return X;
	}
	
	private BigInteger generateGX(BigInteger g, BigInteger p,BigInteger X){
		BigInteger GX = null;
		
		GX = g.modPow(X,p);
		
		return GX;
	}
		//ZKP generate
	private String[] generateZKP(BigInteger g, BigInteger p,BigInteger q,BigInteger X, BigInteger GX,String signerID){
		
		String[] ZKP = new String[2];
		
		BigInteger V = randomNumber();
		BigInteger GV = g.modPow(V,p);
		
		BigInteger h = getSHA256(g,GV,GX,signerID);
		
		BigInteger R = V.subtract(X.multiply(h)).mod(q);
		
		ZKP[0] = byte2HexString(GV.toByteArray());
		ZKP[1] = byte2HexString(R.toByteArray());
		
		return ZKP;
	}
	private boolean verifydZKP(BigInteger g, BigInteger p, BigInteger q, BigInteger GX, BigInteger[] ZKP, String signerID){
		
		BigInteger h = getSHA256(g,ZKP[0],GX,signerID);
		
		if(GX.compareTo(BigInteger.ZERO) == 1 && GX.compareTo(p.subtract(BigInteger.ONE)) == -1 && GX.modPow(q,p).compareTo(BigInteger.ONE) == 0 && g.modPow(ZKP[1],p).multiply(GX.modPow(h,p)).mod(p).compareTo(ZKP[0]) == 0){
			log.info("verifyd match");
			return true;
		}else{
			log.info("verifyd miss match");
			return false;
		}
	}
		
	//hmac
	private JSONObject SymKey(BigInteger inputKey, String cip,String Iv){
			//共通鍵のハッシュ値
			//検証パラメータとして使う文字列
		String VerifyValue = "0123456789ABCDEF";
		String HashString = "Sync-AES_256_CBC-HMAC256";//AES/CBC/SHA256
			//Key(秘密鍵)
		BigInteger symKey = inputKey;
		SecretKeySpec secret_key = null;
		SecretKeySpec Key = null;
		Mac mac = null;
		byte[] aes256Key = null;
		byte[] hmac256key = null;
		byte[] rawHmac = null;
		byte[] secKey = null;
		
		byte[] randomIV = null;
		
		JSONObject obj = new JSONObject();
		/*
		 *この手順で実装を行う
		 *共通の値を計算
		 *０によるMacの関数の初期化
		 *入力データとして共通の値を入力
		 *mac値算出 これを以降の初期化の鍵として用いる
		 *
		 *リセット
		 *HashStringをパラメータとして入力する
		 *数値1をパラメータとして入力する
		 *パディング処理を施した値を取得する(この値をbase64でエンコードした値がaes256keyの値となる)
		 *
		 *次に，aes256keyの値をパラメータとして用いる．
		 *HashStringの値をパラメータとして用いる
		 *数値2をパラメータとして用いる
		 *パディング処理をして結果を得る(この値をbase64でエンコードした値がhmac256keyの値となる)
		 *
		 *と，思われるので，とりあえずこれで構築
		 *
		 */
		
			//初期化用の鍵
		byte[] firstByte = {(byte)0x00,(byte)0x00};
		secret_key = new SecretKeySpec(firstByte,"HmacSHA256");
		
		try{
			mac = Mac.getInstance("HmacSHA256");
				//0により初期化
			mac.init(secret_key);
				//入力データ
				//共通鍵
			mac.update(bytetobyte(symKey.toByteArray()));
			secKey = mac.doFinal();
			
				//鍵として扱う
			Key = new SecretKeySpec(secKey,"HmacSHA256");
				//リセット
			mac.reset();
				//secKeyにより初期化
			mac.init(Key);
				//入力データ
			mac.update(HashString.getBytes());
			mac.update(new Integer(1).byteValue());
				//aes256key
			aes256Key = mac.doFinal();
			
		}catch(Exception e){
			log.error("cipher error",e);
		}
		
			//hmac256key
		try{
			
			mac = Mac.getInstance("HmacSHA256");
				//初期化
			mac.init(Key);
				//入力データ
			mac.update(aes256Key);
			mac.update(HashString.getBytes());
			mac.update(new Integer(2).byteValue());
			hmac256key = mac.doFinal();
		}catch(Exception e){
			log.error("mac error",e);
		}
		
		byte[] ciphertext = null;
		SecretKeySpec secrityKey = new SecretKeySpec(byteAtoB(aes256Key),"AES");
		
		//暗号化
		try{
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			//Iv get base64
			byte[] Ivbyte = Base64.decodeBase64(Iv.getBytes());
			//Iv length 16 byte
			cipher.init(Cipher.ENCRYPT_MODE,secrityKey,new IvParameterSpec(Ivbyte));
				//暗号化
			ciphertext = cipher.doFinal(VerifyValue.getBytes());
		}catch(Exception e){
			log.error("cipher error",e);
		}
			//出力の暗号とIv
		byte[] senderCiphertext = null;
		byte[] senderIv = null;
		try{
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				//Iv length 16 byte
			cipher.init(Cipher.ENCRYPT_MODE,secrityKey);
			senderIv = cipher.getIV();
				//出力用の暗号
			senderCiphertext = cipher.doFinal(VerifyValue.getBytes());
		}catch(Exception e){
			log.error("cipher error",e);
		}
		
		byte[] result = Base64.encodeBase64(ciphertext);
		if(Arrays.equals(cip.getBytes(),result)){
				//一致
			log.info("byte配列の比較 一致");
			/*
			 *クライアントに暗号化して渡す情報は
			 *認証サーバの情報か，それともユーザ名とアクセスした先のURLか
			 *その他検討中
			 *
			 *現状は固定メッセージを暗号化
			 */
			JSONObject obj_Payload = new JSONObject();
			
				//文字列
			char[] resultString = getChars(Base64.encodeBase64(senderCiphertext));
			char[] resultIV = getChars(Base64.encodeBase64(senderIv));
				//mac値取得のための処理
			byte[] hmac = null;
				//secretKey
			SecretKeySpec hmacSecrityKey = new SecretKeySpec(byteAtoB(hmac256key),"HmacSHA256");
				//hmac256key
			try{
				
				mac = Mac.getInstance("HmacSHA256");
					//初期化用鍵
				mac.init(hmacSecrityKey);
					//入力データ
				mac.update(new String().copyValueOf(resultString).getBytes("UTF-8"));
				hmac = mac.doFinal();
			}catch(Exception e){
				log.error("mac error",e);
			}
			
			
				//hmacの数値
			String receiverHmac = byte2HexString(hmac);
			
			
			String senderCip = new String().copyValueOf(resultString);
			String IV = new String().copyValueOf(resultIV);
			obj_Payload.put("cip",senderCip);
			obj_Payload.put("IV",IV);
			obj_Payload.put("hmac",receiverHmac);
			
			obj.put("type","receiver3");
			obj.put("payload",obj_Payload);
			
				//return obj;
		}
		else{
				//不一致
				//他にもいくつか修正してあげる必要がある可能性があるので注意するように
			log.info("byte配列の比較　不一致");
			obj = null;
				//return obj = null;
		}
		return obj;
	}
	private BigInteger getSHA256(BigInteger g, BigInteger GV, BigInteger GX, String signerID){
		
		byte[] gByte = bytetobyte(g.toByteArray());
		byte[] gvByte = bytetobyte(GV.toByteArray());
		byte[] gxByte = bytetobyte(GX.toByteArray());
		
		MessageDigest sha = null;
		
		try{
			sha = MessageDigest.getInstance("SHA-256");
			
			byte[] gLength = new byte[2];
			gLength[0] = (byte)(gByte.length >>> 8);
			gLength[1] = (byte)(gByte.length);
			sha.update(gLength);
			sha.update(gByte);
			
			byte[] grLength = new byte[2];
			grLength[0] = (byte)(gvByte.length >>> 8);
			grLength[1] = (byte)(gvByte.length);
			sha.update(grLength);
			sha.update(gvByte);
			
			byte[] gxLength = new byte[2];
			gxLength[0] = (byte)(gxByte.length >>> 8);
			gxLength[1] = (byte)(gxByte.length);
			sha.update(gxLength);
			sha.update(gxByte);
			
			byte[] signerIDLength = new byte[2];
			signerIDLength[0] = (byte)(signerID.length() >>> 8);
			signerIDLength[1] = (byte)(signerID.length());
			sha.update(signerIDLength);
			sha.update(signerID.getBytes("US-ASCII"));
		}catch(Exception e){
			e.printStackTrace();
		}
		return new BigInteger(1,sha.digest());
	}
	public String byte2HexString(byte[] input){
		StringBuilder output =  new StringBuilder();
		input = bytetobyte(input);
		for(int i = 0; i < input.length; i++){
			if((input[i] & 0xFF) < 0x10){
				output.append("0");
			}
			output.append(Integer.toHexString(input[i] & 0xFF));
		}
		return output.toString();
	}
		//384 or 32
	public byte[] bytetobyte(byte[] input){
		
		int length = 0;
		if(input.length > MaxLength){
			length = input.length - MaxLength;
		}
		else if(input.length == MinLength){
			length = input.length - (MinLength - 1);
		}
		byte[] output = new byte[input.length - length];
		if(input.length > MaxLength || input.length == MinLength){
			for(int i = 0; i < input.length - length; i++){
				output[i] = input[i + length];
			}
		}else{
			output = input;
		}
		return output;
	}
	
	//JSONParse
	private void JSONParse(HttpServletRequest request, String payload,HashMap output,String round){
			//HashMap output = new HashMap();
		HttpSession session = request.getSession();
		JSONObject jObject = null;
		if(payload.length() != 0){
			jObject = JSONObject.fromObject(payload);
			if(round.equals("Round1")){
				
				String[] senderZKP1 = {(String)jObject.optJSONObject("payload").getJSONObject("zkp_x1").optString("gr"),(String)jObject.optJSONObject("payload").getJSONObject("zkp_x1").optString("b")};
				
				String[] senderZKP2 = {(String)jObject.optJSONObject("payload").getJSONObject("zkp_x2").optString("gr"),(String)jObject.optJSONObject("payload").getJSONObject("zkp_x2").optString("b")};
				String gx1 = (String)jObject.optJSONObject("payload").optString("gx1");
				String gx2 = (String)jObject.optJSONObject("payload").optString("gx2");
				String message = jObject.optJSONObject("payload").getJSONObject("zkp_x1").optString("id");
				
				//requestの検証
				//BigInteger g, BigInteger p, BigInteger q, BigInteger GX, BigInteger[] ZKP, String signerID
				//通過すればセッションに記録するためのhashmapに追加
				
				BigInteger[] senderZKP1_int = {new BigInteger(senderZKP1[0],16),new BigInteger(senderZKP1[1],16)};
				BigInteger[] senderZKP2_int = {new BigInteger(senderZKP2[0],16),new BigInteger(senderZKP2[1],16)};
				
				BigInteger gx1_int = new BigInteger(gx1,16);
				BigInteger gx2_int = new BigInteger(gx2,16);
				
				
					//下記検証式でtrueにならない事例有．また要修正
					//if(verifydZKP(this.g,this.p,this.q,gx1_int,senderZKP1_int,message) == true && verifydZKP(this.g,this.p,this.q,gx2_int,senderZKP2_int,message) == true){
					
				log.info("parse round 1");
				output.put("type",jObject.optString("type"));
				output.put("GX1",jObject.optJSONObject("payload").optString("gx1"));
				output.put("GX2",jObject.optJSONObject("payload").optString("gx2"));
				output.put("senderZKP1",senderZKP1);
				output.put("senderZKP2",senderZKP2);
				output.put("message",message);
				output.put("userID",jObject.optJSONObject("payload").optString("user"));
				/*log.info((String)output.get("type"));
				log.info((String)output.get("GX1"));
				log.info((String)output.get("GX2"));
				log.info((String)output.get("message"));
				log.info((String)output.get("userID"));
				}else{
					
				}*/
			}
			else if(round.equals("Round2")){
				/*
				String A = jObject.optJSONObject("payload").optString("A");
				 */
				/*
				String[] senderZKPA = {(String)jObject.optJSONObject("payload").getJSONObject("zkp_A").optString("gr"),(String)jObject.optJSONObject("payload").getJSONObject("zkp_A").optString("b")};
				*/
					//String A = (String)jObject.optJSONObject("payload").optString("A");
								
				output.put("A",jObject.optJSONObject("payload").optString("A"));
				
				/******
				 *記録出来ない事例が出来てたため，セッションへ記録する
				 ******/
				output.put("sendarZKPA0",jObject.optJSONObject("payload").getJSONObject("zkp_A").optString("gr"));
				output.put("senderZKPA1",jObject.optJSONObject("payload").getJSONObject("zkp_A").optString("b"));
					//セッションへ記録
				session.setAttribute("senderZKP0",jObject.optJSONObject("payload").getJSONObject("zkp_A").optString("gr"));
				session.setAttribute("sendrrZKP1",jObject.optJSONObject("payload").getJSONObject("zkp_A").optString("b"));
				
				output.put("message",jObject.optJSONObject("payload").getJSONObject("zkp_A").optString("id"));
				
			}
			else if(round.equals("Final")){
				output.put("cip",jObject.optJSONObject("payload").optString("cip"));
				output.put("IV",jObject.optJSONObject("payload").optString("IV"));
			}
			else{
			}
			
		}
		
			//return output;
	}
		//byte 32
	private byte[] byteAtoB(byte[] input){
		
		byte[] output = new byte[32];
		int length = input.length;
		
			//32以上
		if(length > 32){
			for(int i = 0; i < 32; i++){
				output[i] = input[i];
			}
		}else{
			output = input;
		}
		return output;
	}
	
		//getChars
	private char[] getChars(byte[] input){
		ArrayList<Character> resultChars = new ArrayList<Character>();
		
		Reader reader = null;
		
		try{
			reader = new InputStreamReader(new ByteArrayInputStream(input),"US-ASCII");
			
			char[] cbuf = new char[2048];
			for(int len = 0; len != -1; len = reader.read(cbuf,0,cbuf.length)){
				for(int i = 0; i < len; i++){
					resultChars.add(Character.valueOf(cbuf[i]));
				}
			}
		}catch(Exception e){
			
		}finally{
			closeStream(reader);
		}
		return toCharArray(resultChars);
	}
	
	private void closeStream(Closeable... streams){
		for(Closeable stream : streams){
			try{
				if(stream != null) stream.close();
			}catch(Exception e){
			}
		}	
	}
	private char[] toCharArray(List<Character> charList){
		char[] charArray = new char[charList.size()];
		int i = 0;
		
		for(Character ch : charList){
			charArray[i++] = ch.charValue();
		}
		return charArray;
	}
	//vt.Ldapsearch
	/*
	 *記録されているパスワード取得
	 */
	protected String testSearch(String searchfilter)throws NamingException{
			//Ldapサーバへアクセスする
			//login.confのファイルはシステムから
		String config = System.getProperty("java.security.auth.login.config");
		config = config.substring(7,config.length());
		Properties prop = new Properties();
		
		try{
			prop.load(new FileInputStream(config));
		}catch(IOException e){
				//log.error(e);
			return;
		}
		
			//アクセス先の指定
			//LdapPool
			//DefaultLdapFactory factory = new DefaultLdapFactory(new LdapConfig("ldap://localhost","o=test_o,dc=ac,c=JP"));
			//ldapUrl & baseDn
		String ldapUrl = prop.getProperty("ldapUrl");
		String baseDn = prop.getProperty("baseDn");
		
			//log.info("ldapUrl & baseDn = " + ldapUrl + " baseDn " + baseDn);
		
		ldapUrl = ldapUrl.substring(1,(ldapUrl.length()-1));
		baseDn = baseDn.substring(1,(baseDn.length()-1));
		
		DefaultLdapFactory factory = new DefaultLdapFactory(new LdapConfig(ldapUrl.toString(),baseDn.toString()));
		
		SoftLimitLdapPool pool = new SoftLimitLdapPool(factory);
		
		pool.initialize();
		
		Ldap ldap = null;
		String result = null;
		
		Attributes attrs = null;
		Attribute attr = null;
		String pass = null;
		try{
			ldap = pool.checkOut();
			
			Iterator<SearchResult> i = ldap.search(new SearchFilter("uid=" + searchfilter),new String[]{"uid","userPassword"});
			
			while(i.hasNext()) {
				SearchResult str = i.next();				
					//Attributes取得
				attrs = str.getAttributes();
				
					//Attributesから属性の列挙を取得
				attr = attrs.get("userPassword");
					//object → byte → String
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				ObjectOutputStream oos = new ObjectOutputStream(baos);
				
				Object testObj = attr.get();
				
				oos.writeObject(testObj);
				
				byte[] bytes = baos.toByteArray();
				String testString = baos.toString();
				
				oos.close();
				baos.close();
                
                ByteArrayInputStream inBytes = new ByteArrayInputStream(bytes);
                ObjectInputStream inObject = new ObjectInputStream(inBytes);
                
                char passChar = getChars((byte[])inObject.readObject());
                
                inbytes.close();
                inObject.close();
                
                //パスワード文字列をresultに代入
				result = new String.copyValueOf(passChar);
                
            }
        }catch (Exception e) {
			log.error("error using the ldap pool.",e);
		}finally{
			pool.checkIn(ldap);
		}
		pool.close();
        
        return result;
    }
}
