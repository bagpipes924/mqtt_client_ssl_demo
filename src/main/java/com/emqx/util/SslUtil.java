package com.emqx.util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManager;

public class SslUtil {
	private final static Logger logger = LoggerFactory.getLogger(SslUtil.class);
	public static SSLSocketFactory getSocketFactory(final String caCrtFile, final String crtFile, final String keyFile,final String password) throws Exception {
		//Security.addProvider(new BouncyCastleProvider());
		PEMReader reader=null;
		// load CA certificate
		TrustManager[] tms={ new TrustAllManager() };
		if(caCrtFile!=null) {
			reader = new PEMReader(new InputStreamReader(new ByteArrayInputStream(Files.readAllBytes(Paths.get(caCrtFile)))));
			X509Certificate caCert = (X509Certificate) reader.readObject();
			reader.close();
			// CA certificate is used to authenticate server
			KeyStore caKs = KeyStore.getInstance(KeyStore.getDefaultType());
			caKs.load(null, null);
			caKs.setCertificateEntry("ca-certificate", caCert);
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(caKs);
			tms=tmf.getTrustManagers();
		}
		
		
		KeyManager[] kms=null;
		// load client certificate and private key
		if(crtFile!=null &&keyFile!=null) {
			reader = new PEMReader(new InputStreamReader(new ByteArrayInputStream(Files.readAllBytes(Paths.get(crtFile)))));
			X509Certificate cert = (X509Certificate) reader.readObject();
			reader.close();
			
			reader = new PEMReader(new InputStreamReader(new ByteArrayInputStream(Files.readAllBytes(Paths.get(keyFile)))),
					new PasswordFinder() {
						public char[] getPassword() {
							return password.toCharArray();
						}
					});
			KeyPair key = (KeyPair) reader.readObject();
			reader.close();
			
			// client key and certificates are sent to server so it can authenticate
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(null, null);
			ks.setCertificateEntry("certificate", cert);
			ks.setKeyEntry("private-key", key.getPrivate(), password.toCharArray(),
					new java.security.cert.Certificate[] { cert });
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(ks, password.toCharArray());
			kms=kmf.getKeyManagers();
		}
		

		// finally, create SSL socket factory
		SSLContext context = SSLContext.getInstance("TLS");
		context.init(kms, tms, new SecureRandom());
		return context.getSocketFactory();
	}
	
	
	public static SSLSocketFactory getSSLSocktet(String caPath, String crtPath, String keyPath, String password) {
        try{
        	char[] passwordChar=null;
        	if (password!=null) {
        		passwordChar=password.toCharArray();
			}
        	
            CertificateFactory cAf = CertificateFactory.getInstance("X.509");
            FileInputStream caIn = new FileInputStream(caPath);
            X509Certificate ca = (X509Certificate) cAf.generateCertificate(caIn);
            KeyStore caKs = KeyStore.getInstance("JKS");
            caKs.load(null, null);
            caKs.setCertificateEntry("ca-certificate", ca);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(caKs);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            FileInputStream crtIn = new FileInputStream(crtPath);
            X509Certificate caCert = (X509Certificate) cf.generateCertificate(crtIn);

            crtIn.close();
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry("certificate", caCert);
            PrivateKey privateKey=getPrivateKey(keyPath);
            ks.setKeyEntry(password, privateKey.getEncoded(), new Certificate[]{caCert});
            //ks.setKeyEntry("private-key",privateKey,passwordChar,new Certificate[]{caCert});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());//"PKIX"
            kmf.init(ks, passwordChar);

            SSLContext context = SSLContext.getInstance("TLSv1");

            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
            return context.getSocketFactory();
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public static PrivateKey getPrivateKey(String path) throws Exception {
        Base64 base64 = new Base64();
        byte[] buffer = base64.decode(getPem(path));

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

    }

    private static String getPem(String path) throws Exception {
        FileInputStream fin = new FileInputStream(path);
        BufferedReader br = new BufferedReader(new InputStreamReader(fin));
        String readLine = null;
        StringBuilder sb = new StringBuilder();
        while ((readLine = br.readLine()) != null) {
            if (readLine.charAt(0) == '-') {
                continue;
            } else {
                sb.append(readLine);
                sb.append('\r');
            }
        }
        fin.close();
        return sb.toString();
    }
}
