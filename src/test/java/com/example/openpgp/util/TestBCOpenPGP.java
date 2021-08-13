package com.example.openpgp.util;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;


class TestBCOpenPGP {

	// Make this true if you want the share public key file
	// More form here https://stackoverflow.com/questions/24358996/when-and-why-decorate-outputstream-with-armoredoutputstream-when-using-bouncycas
	
	private boolean isArmored = true;
	private String id = "example";
	private String passwd = "Test@123";
	private boolean integrityCheck = true;


	private String pubKeyFile = "/Users/k0d03gd/project/poc/code/open-pgp-java/src/main/resources/keys/pub.dat";
	private String privKeyFile = "/Users/k0d03gd/project/poc/code/open-pgp-java/src/main/resources/keys/secret.dat";

	private String plainTextFile = "/Users/k0d03gd/project/poc/code/open-pgp-java/src/main/resources/keys/plain-text.txt"; //create a text file to be encripted, before run the tests
	private String cipherTextFile = "/Users/k0d03gd/project/poc/code/open-pgp-java/src/main/resources/keys/cypher-text.dat";
	private String decPlainTextFile = "/Users/k0d03gd/project/poc/code/open-pgp-java/src/main/resources/keys/dec-plain-text.txt";
	private String signatureFile = "/Users/k0d03gd/project/poc/code/open-pgp-java/src/main/resources/keys/signature.txt";

	@Test
	void genKeyPair() throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {

		RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();

		Security.addProvider(new BouncyCastleProvider());

		KeyPairGenerator    kpg = KeyPairGenerator.getInstance("RSA", "BC");

		kpg.initialize(1024);

		KeyPair                    kp = kpg.generateKeyPair();

		FileOutputStream    out1 = new FileOutputStream(privKeyFile);
		FileOutputStream    out2 = new FileOutputStream(pubKeyFile);

		rkpg.exportKeyPair(out1, out2, kp.getPublic(), kp.getPrivate(), id, passwd.toCharArray(), isArmored);
	}

	@Test
	void encrypt() throws NoSuchProviderException, IOException, PGPException{
		FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
		FileOutputStream cipheredFileIs = new FileOutputStream(cipherTextFile);
		PgpHelper.getInstance().encryptFile(cipheredFileIs, plainTextFile, PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);
		cipheredFileIs.close();
		pubKeyIs.close();
	}

	@Test
	void decrypt() throws Exception{

		FileInputStream cipheredFileIs = new FileInputStream(cipherTextFile);
		FileInputStream privKeyIn = new FileInputStream(privKeyFile);
		FileOutputStream plainTextFileIs = new FileOutputStream(decPlainTextFile);
		PgpHelper.getInstance().decryptFile(cipheredFileIs, plainTextFileIs, privKeyIn, passwd.toCharArray());
		cipheredFileIs.close();
		plainTextFileIs.close();
		privKeyIn.close();
	}

	@Test
	public void signAndVerify() throws Exception{
		FileInputStream privKeyIn = new FileInputStream(privKeyFile);
		FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
		FileInputStream plainTextInput = new FileInputStream(plainTextFile);
		FileOutputStream signatureOut = new FileOutputStream(signatureFile);
				
		byte[] bIn = PgpHelper.getInstance().inputStreamToByteArray(plainTextInput);
		byte[] sig = PgpHelper.getInstance().createSignature(plainTextFile, privKeyIn, signatureOut, passwd.toCharArray(), true);
		PgpHelper.getInstance().verifySignature(plainTextFile, sig, pubKeyIs);
	}

}
