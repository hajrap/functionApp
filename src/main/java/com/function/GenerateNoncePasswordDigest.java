package com.function;
import java.util.*;

import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.HttpMethod;
import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
public class GenerateNoncePasswordDigest{

/****** START SET/GET METHOD, DO NOT MODIFY *****/
	protected String password = "";
	protected String encodedNonce = "";
	protected String passwordDigest = "";
	protected String createdTimestamp = "";
	public String getpassword() {
		return password;
	}
	public void setpassword(String val) {
		password = val;
	}
	public String getencodedNonce() {
		return encodedNonce;
	}
	public void setencodedNonce(String val) {
		encodedNonce = val;
	}
	public String getpasswordDigest() {
		return passwordDigest;
	}
	public void setpasswordDigest(String val) {
		passwordDigest = val;
	}
	public String getcreatedTimestamp() {
		return createdTimestamp;
	}
	public void setcreatedTimestamp(String val) {
		createdTimestamp = val;
	}
/****** END SET/GET METHOD, DO NOT MODIFY *****/

/*****START OF USED FUNCTION DEFINATIONS *****/

SimpleDateFormat dateFormat = null;
MessageDigest shaMessageDigest = null;
private static Random randomGenerator;
private final byte[] nonceGenerationKey = {0x01, 0x02, 0x05, 0x06, 0x04};

 private SimpleDateFormat getDateFormat() {
	
        if (dateFormat == null) {
             dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
             dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        }
        return dateFormat;
    }

 private MessageDigest getSHADigest() throws NoSuchAlgorithmException {
	
        if (shaMessageDigest == null) {
            shaMessageDigest = MessageDigest.getInstance("SHA1");
        }
        shaMessageDigest.reset();
        return shaMessageDigest;
   }

 private  byte[] getSeed() {
        if (randomGenerator == null) {
            try {
                randomGenerator = SecureRandom.getInstance("SHA1PRNG");
            } catch (NoSuchAlgorithmException ex) {
                  randomGenerator = new Random(System.currentTimeMillis());
            }
        }
        return Long.toString(randomGenerator.nextLong()).getBytes();
    }

 public static String encodeString (String s) {
   return new String(encode(new String(s).getBytes())); }

 public static char[] encode (byte[] in) {
   return encode(in,in.length); }

 public static char[] encode (byte[] in, int iLen) {
   int oDataLen = (iLen*4+2)/3;       // output length without padding
   int oLen = ((iLen+2)/3)*4;         // output length including padding
   char[] out = new char[oLen];
   int ip = 0;
   int op = 0;
   while (ip < iLen) {
      int i0 = in[ip++] & 0xff;
      int i1 = ip < iLen ? in[ip++] & 0xff : 0;
      int i2 = ip < iLen ? in[ip++] & 0xff : 0;
      int o0 = i0 >>> 2;
      int o1 = ((i0 &   3) << 4) | (i1 >>> 4);
      int o2 = ((i1 & 0xf) << 2) | (i2 >>> 6);
      int o3 = i2 & 0x3F;
      out[op++] = map1[o0];
      out[op++] = map1[o1];
      out[op] = op < oDataLen ? map1[o2] : '='; op++;
      out[op] = op < oDataLen ? map1[o3] : '='; op++; }
   return out; 
  }
 
// Mapping table from 6-bit nibbles to Base64 characters.
 private static char[]    map1 = new char[64];
   static {
      int i=0;
      for (char c='A'; c<='Z'; c++) map1[i++] = c;
      for (char c='a'; c<='z'; c++) map1[i++] = c;
      for (char c='0'; c<='9'; c++) map1[i++] = c;
      map1[i++] = '+'; map1[i++] = '/'; }

// Mapping table from Base64 characters to 6-bit nibbles.
 private static byte[]    map2 = new byte[128];
   static {
      for (int i=0; i<map2.length; i++) map2[i] = -1;
      for (int i=0; i<64; i++) map2[map1[i]] = (byte)i; }
 
  private String generatePasswordDigest(final String nonce, final String createdTimeStamp, final String password) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = getSHADigest();
        messageDigest.update(nonce.getBytes());
        messageDigest.update(createdTimeStamp.getBytes());
        messageDigest.update(password.getBytes());
        byte[] digest = messageDigest.digest();
        return new String(encode(digest));
    }
/*****END OF USED FUNCTION DEFINATIONS *****/

	public GenerateNoncePasswordDigest() {
	}
	public void invoke() throws Exception {
/* Available Variables: DO NOT MODIFY
	In  : String password
	Out : String encodedNonce
	Out : String passwordDigest
	Out : String createdTimestamp
* Available Variables: DO NOT MODIFY *****/


  createdTimestamp = getDateFormat().format(Calendar.getInstance().getTime());
  MessageDigest messageDigest = getSHADigest();
  messageDigest.update(getSeed());
  messageDigest.update(nonceGenerationKey);
  String generatedNonce = new String(messageDigest.digest());
  passwordDigest = generatePasswordDigest(generatedNonce, createdTimestamp, password);
  encodedNonce = encodeString(generatedNonce);

}
@FunctionName("GenerateNoncePasswordDigest")
public HttpResponseMessage run(
        @HttpTrigger(
            name = "req",
            methods = {HttpMethod.GET, HttpMethod.POST},
            authLevel = AuthorizationLevel.ANONYMOUS)
            HttpRequestMessage<Optional<String>> request,
        final ExecutionContext context) throws Exception {
    context.getLogger().info("Java HTTP trigger processed a request.");


    invoke();
    ArrayList<String> responseArrayList = new ArrayList<>();
    responseArrayList.add( password );
    responseArrayList.add( createdTimestamp );
    responseArrayList.add(encodedNonce );
    responseArrayList.add(passwordDigest );
    return request.createResponseBuilder(HttpStatus.OK).body(responseArrayList).build();
}
}
