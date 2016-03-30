package tcp_pki_v;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.*;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
public class Router2 {
	private static String[] route = Planner.route;
	public static KeyPair generateKeyPair () throws NoSuchAlgorithmException {
		// Generate a key-pair
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(512); // 512 is the keysize.
		KeyPair kp = kpg.generateKeyPair();
		return kp;
	}
	
	private static byte[] encrypt(byte[] inpBytes, PrivateKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}
	
	private static void sendPublickey(KeyPair kp, int portNumber) throws UnknownHostException, IOException{
		String xform = "RSA/ECB/NoPadding";
		BufferedReader inFromClient1 = new BufferedReader( new InputStreamReader(System.in));
		Socket client1Socket = new Socket("localhost", portNumber);
		DataOutputStream outToClient3 = new DataOutputStream(client1Socket.getOutputStream());
		PublicKey pubk = kp.getPublic();
		String encoded = Base64.getEncoder().encodeToString(pubk.getEncoded());
		outToClient3.writeBytes(encoded + '\n');
		outToClient3.close();
	}
	
	private static byte[] readMsgFromClient1(int portNumber) throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException{
		ServerSocket client1MsgSocket = new ServerSocket(portNumber);
		while(true){
			Socket connectionSocket = client1MsgSocket.accept();
			BufferedReader inFromClient1 = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream())); 
			String msg = inFromClient1.readLine(); 
			byte[] decodedMsg = Base64.getDecoder().decode(msg);
			return decodedMsg;
		}
	}
	
	private static void sendMsgToClient3(KeyPair kp, byte[] msg,int portNumber) throws Exception {
		String xform = "RSA/ECB/NoPadding";
		PrivateKey prvk = kp.getPrivate();
		Socket router2Socket = new Socket("localhost", portNumber);
		DataOutputStream outToClient3 = new DataOutputStream(router2Socket.getOutputStream());
		byte[] encryptedMsg = encrypt(msg, prvk, xform);
		String encodedMsg = Base64.getEncoder().encodeToString(encryptedMsg);
		outToClient3.writeBytes(encodedMsg + '\n');
		outToClient3.close();
	}
	
	public static void main(String[] args) throws Exception {
		String xform = "RSA/ECB/NoPadding";
 		KeyPair router2_kp = Router2.generateKeyPair();
 		int publicKeySenderPort = 4445;
 		int client1MsgPort = 6789;
 		int toClient3Port = 5678;
 		Router2.sendPublickey(router2_kp, publicKeySenderPort);
 		byte[] msgFromClient1 = Router2.readMsgFromClient1(client1MsgPort);
		System.out.println("MsgFromClient1 Size: " + msgFromClient1.length);
 		Router2.sendMsgToClient3(router2_kp, msgFromClient1, toClient3Port);
	}

}
