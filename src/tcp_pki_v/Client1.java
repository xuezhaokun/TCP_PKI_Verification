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
import java.util.Base64;
public class Client1 {
	private static String[] route = {"Client1", "Router2", "Client3"};
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
