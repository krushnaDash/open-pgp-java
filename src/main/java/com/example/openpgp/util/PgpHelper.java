package com.claims.risk.cdi.util;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

public class PgpHelper {

	private static PgpHelper INSTANCE = null;

	public static PgpHelper getInstance() {

		if (INSTANCE == null)
			INSTANCE = new PgpHelper();
		return INSTANCE;
	}

	private PgpHelper() {
	}

	public PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in),
				new JcaKeyFingerprintCalculator());

		Iterator keyRingIter = pgpPub.getKeyRings();

		while (keyRingIter.hasNext()) {
			PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();
			Iterator keyIter = keyRing.getPublicKeys();

			while (keyIter.hasNext()) {
				PGPPublicKey key = (PGPPublicKey) keyIter.next();

				if (key.isEncryptionKey()) {
					return key;
				}
			}
		}

		throw new IllegalArgumentException("Can't find encryption key in key ring.");
	}

	public static PGPSecretKey readSecretKeyFromCol(InputStream in, long keyId) throws IOException, PGPException {
		in = PGPUtil.getDecoderStream(in);
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in, new BcKeyFingerprintCalculator());

		PGPSecretKey key = pgpSec.getSecretKey(keyId);

		if (key == null) {
			throw new IllegalArgumentException("Can't find encryption key in key ring.");
		}
		return key;
	}

	/**
	 * THis method can be used to decrypt a file which is encrypted using gpg
	 * 
	 * @param in
	 * @param secKeyIn
	 * @param pubKeyIn
	 * @param pass
	 * @throws IOException
	 * @throws PGPException
	 */
	public void decryptFileGPG(InputStream in, InputStream secKeyIn, InputStream pubKeyIn, char[] pass)
			throws IOException, PGPException {
		Security.addProvider(new BouncyCastleProvider());

		PGPPublicKey pubKey = readPublicKey(pubKeyIn);

		PGPSecretKey secKey = readSecretKeyFromCol(secKeyIn, pubKey.getKeyID());

		in = PGPUtil.getDecoderStream(in);

		JcaPGPObjectFactory pgpFact;

		PGPObjectFactory pgpF = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());

		Object o = pgpF.nextObject();
		PGPEncryptedDataList encList;

		if (o instanceof PGPEncryptedDataList) {

			encList = (PGPEncryptedDataList) o;

		} else {

			encList = (PGPEncryptedDataList) pgpF.nextObject();

		}

		Iterator<PGPEncryptedData> itt = encList.getEncryptedDataObjects();
		PGPPrivateKey sKey = null;
		PGPPublicKeyEncryptedData encP = null;
		while (sKey == null && itt.hasNext()) {
			encP = (PGPPublicKeyEncryptedData) itt.next();
			sKey = secKey.extractPrivateKey(
					new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass));
		}
		if (sKey == null) {
			throw new IllegalArgumentException("Secret key for message not found.");
		}

		InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));

		pgpFact = new JcaPGPObjectFactory(clear);

		PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();

		pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

		Object data = pgpFact.nextObject();
		PGPLiteralData ld;

		if (data instanceof PGPLiteralData) {
			ld = (PGPLiteralData) data;
		} else {
			ld = (PGPLiteralData) pgpFact.nextObject();
		}

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		InputStream inLd = ld.getDataStream();

		int ch;
		while ((ch = inLd.read()) >= 0) {
			bOut.write(ch);
		}

		System.out.println(bOut.toString());

		// bOut.writeTo(new FileOutputStream(ld.getFileName()));
		// return bOut;

	}

	/**
	 * decrypt the passed in message stream
	 */
	@SuppressWarnings("unchecked")
	public void decryptFile(InputStream in, OutputStream out, InputStream keyIn, char[] passwd) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);

		PGPObjectFactory pgpFact1 = new BcPGPObjectFactory(in);
		PGPEncryptedDataList encDataList = (PGPEncryptedDataList) pgpFact1.nextObject();

		PGPSecretKeyRingCollection privateKeyRings = new BcPGPSecretKeyRingCollection(in);

		PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encDataList.get(0);

		//
		// find the secret key
		//

		PGPPrivateKey sKey = null;

		sKey = findSecretKey(keyIn, encData.getKeyID(), passwd);

		if (sKey == null) {
			throw new IllegalArgumentException("Secret key for message not found.");
		}

		PublicKeyDataDecryptorFactory b = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC")
				.setContentProvider("BC").build(sKey);

		InputStream clear = encData.getDataStream(b);

		PGPObjectFactory plainFact = new BcPGPObjectFactory(clear);

		Object message = plainFact.nextObject();

		if (message instanceof PGPCompressedData) {
			PGPCompressedData cData = (PGPCompressedData) message;
			PGPObjectFactory pgpFact = new BcPGPObjectFactory(cData.getDataStream());

			message = pgpFact.nextObject();
		}

		if (message instanceof PGPLiteralData) {
			PGPLiteralData ld = (PGPLiteralData) message;
			InputStream unc = ld.getInputStream();
			int ch;
			while ((ch = unc.read()) >= 0) {
				out.write(ch);
			}
		} else if (message instanceof PGPOnePassSignatureList) {
			throw new PGPException("Encrypted message contains a signed message - not literal data.");
		} else {
			throw new PGPException("Message is not a simple encrypted file - type unknown.");
		}

		if (encData.isIntegrityProtected()) {
			if (!encData.verify()) {
				throw new PGPException("Message failed integrity check");
			}
		}
	}

	/**
	 * Load a secret key ring collection from keyIn and find the secret key
	 * corresponding to keyID if it exists.
	 *
	 * @param keyIn input stream representing a key ring collection.
	 * @param keyID keyID we want.
	 * @param pass  passphrase to decrypt secret key with.
	 * @return
	 * @throws IOException
	 * @throws PGPException
	 * @throws NoSuchProviderException
	 */
	public PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass)
			throws IOException, PGPException, NoSuchProviderException {
		PGPSecretKeyRingCollection pgpSec = new BcPGPSecretKeyRingCollection(
				org.bouncycastle.openpgp.PGPUtil.getDecoderStream(keyIn));

		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

		if (pgpSecKey == null) {
			return null;
		}

		PBESecretKeyDecryptor a = new JcePBESecretKeyDecryptorBuilder(
				new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(pass);

		return pgpSecKey.extractPrivateKey(a);
	}

	public void encryptFile(OutputStream out, String fileName, PGPPublicKey encKey, boolean armor,
			boolean withIntegrityCheck) throws IOException, NoSuchProviderException, PGPException {
		Security.addProvider(new BouncyCastleProvider());

		if (armor) {
			out = new ArmoredOutputStream(out);
		}

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

		org.bouncycastle.openpgp.PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY,
				new File(fileName));

		comData.close();

		JcePGPDataEncryptorBuilder c = new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
				.setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC");

		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(c);

		JcePublicKeyKeyEncryptionMethodGenerator d = new JcePublicKeyKeyEncryptionMethodGenerator(encKey)
				.setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());

		cPk.addMethod(d);

		byte[] bytes = bOut.toByteArray();

		OutputStream cOut = cPk.open(out, bytes.length);

		cOut.write(bytes);

		cOut.close();

		out.close();
	}

	public byte[] inputStreamToByteArray(InputStream is) throws IOException {

		ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		int nRead;
		byte[] data = new byte[1024];

		while ((nRead = is.read(data, 0, data.length)) != -1) {
			buffer.write(data, 0, nRead);
		}

		buffer.flush();

		return buffer.toByteArray();
	}

	/**
	 * verify the signature in in against the file fileName.
	 */
	public void verifySignature(String fileName, byte[] b, InputStream keyIn)
			throws GeneralSecurityException, IOException, PGPException {
		// in = PGPUtil.getDecoderStream(in);

		PGPObjectFactory pgpFact = new BcPGPObjectFactory(b);
		PGPSignatureList p3 = null;

		Object o = pgpFact.nextObject();
		if (o instanceof PGPCompressedData) {
			PGPCompressedData c1 = (PGPCompressedData) o;

			pgpFact = new BcPGPObjectFactory(c1.getDataStream());

			p3 = (PGPSignatureList) pgpFact.nextObject();
		} else {
			p3 = (PGPSignatureList) o;
		}

		PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(
				PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

		InputStream dIn = new BufferedInputStream(new FileInputStream(fileName));

		PGPSignature sig = p3.get(0);
		PGPPublicKey key = pgpPubRingCollection.getPublicKey(sig.getKeyID());

		sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider(new BouncyCastleProvider()), key);

		int ch;
		while ((ch = dIn.read()) >= 0) {
			sig.update((byte) ch);
		}

		dIn.close();

		if (sig.verify()) {
			System.out.println("signature verified.");
		} else {
			System.out.println("signature verification failed.");
		}
	}

	public PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input),
				new JcaKeyFingerprintCalculator());

		//
		// we just loop through the collection till we find a key suitable for
		// encryption, in the real
		// world you would probably want to be a bit smarter about this.
		//

		Iterator keyRingIter = pgpSec.getKeyRings();
		while (keyRingIter.hasNext()) {
			PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

			Iterator keyIter = keyRing.getSecretKeys();
			while (keyIter.hasNext()) {
				PGPSecretKey key = (PGPSecretKey) keyIter.next();

				if (key.isSigningKey()) {
					return key;
				}
			}
		}

		throw new IllegalArgumentException("Can't find signing key in key ring.");
	}

	public byte[] createSignature(String fileName, InputStream keyIn, OutputStream out, char[] pass, boolean armor)
			throws GeneralSecurityException, IOException, PGPException {

		PGPSecretKey pgpSecKey = readSecretKey(keyIn);
		PGPPrivateKey pgpPrivKey = pgpSecKey.extractPrivateKey(
				new JcePBESecretKeyDecryptorBuilder().setProvider(new BouncyCastleProvider()).build(pass));
		PGPSignatureGenerator sGen = new PGPSignatureGenerator(
				new JcaPGPContentSignerBuilder(pgpSecKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1)
						.setProvider(new BouncyCastleProvider()));

		sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		ArmoredOutputStream aOut = new ArmoredOutputStream(byteOut);

		BCPGOutputStream bOut = new BCPGOutputStream(byteOut);

		InputStream fIn = new BufferedInputStream(new FileInputStream(fileName));

		int ch;
		while ((ch = fIn.read()) >= 0) {
			sGen.update((byte) ch);

		}

		aOut.endClearText();

		fIn.close();

		sGen.generate().encode(bOut);

		if (armor) {
			aOut.close();
		}

		return byteOut.toByteArray();
	}

}
