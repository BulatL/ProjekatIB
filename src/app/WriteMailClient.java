package app;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.mail.internet.MimeMessage;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.google.api.services.gmail.Gmail;

import keystore.KeyStoreReader;
import model.keystore.IssuerData;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {

	// private static final String KEY_FILE = "./data/session.key";
	private static Certificate cert = null;

	static {
		// staticka inicijalizacija
		Security.addProvider(new BouncyCastleProvider());
		org.apache.xml.security.Init.init();
	}

	public static void main(String[] args) {

		try {
			Gmail service = getGmailService();

			// Unos podataka
			System.out.println("Insert a reciever:");
			BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
			String reciever = reader.readLine();

			System.out.println("Insert a subject:");
			String subject = reader.readLine();

			System.out.println("Insert body:");
			String body = reader.readLine();

			// kreiraj xml dokument
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

			Document doc = docBuilder.newDocument();
			Element rootElement = doc.createElement("mail");

			rootElement.setTextContent(body);
			doc.appendChild(rootElement);

			// dokument pre enkripcije
			String xml = xmlAsString(doc);
			System.out.println("Mail pre enkripcije: " + xml);

			// generisanje tajnog (session) kljuca
			SecretKey secretKey = generateSessionKey();

			// citanje keystore-a kako bi se izvukao sertifikat primaoca
			// i kako bi se dobio njegov javni kljuc
			PublicKey publicKey = getPublicKey();

			// inicijalizacija radi sifrovanja teksta mail-a
			XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_128);
			xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);

			// inicijalizacija radi sifrovanja tajnog (session) kljuca javnim RSA kljucem
			XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
			keyCipher.init(XMLCipher.WRAP_MODE, publicKey);

			// TODO 3: kreiranje EncryptedKey objekta koji sadrzi enkriptovan tajni
			// (session) kljuc
			EncryptedKey encryptedKey = keyCipher.encryptKey(doc, secretKey);;
			System.out.println("Kriptovan tajni kljuc: " + encryptedKey);
			
			//TODO 4: kreiranje KeyInfo objekta, postavljanje naziva i enkriptovanog tajnog kljuca
			KeyInfo keyInfo = new KeyInfo(doc);
		    keyInfo.addKeyName("Kriptovani tajni kljuc");
	        //postavljamo kriptovani kljuc
		    keyInfo.add(encryptedKey);
			
			//TODO 5: kreiranje EncryptedData objekata, postavljanje KeyInfo objekata
			//postavljamo KeyInfo za element koji se kriptuje
			EncryptedData encryptedData = xmlCipher.getEncryptedData();
	        encryptedData.setKeyInfo(keyInfo);

			//TODO 6: kriptovati sadrzaj dokumenta
	        NodeList mails = doc.getElementsByTagName("mail");
			Element mail = (Element) mails.item(0);
			
			xmlCipher.doFinal(doc, mail, true);//kriptuje se sadrzaj

			// Slanje poruke
			String encryptedXml = xmlAsString(doc);
			System.out.println("Mail posle enkripcije: " + encryptedXml);

			MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, subject, encryptedXml);
			MailWritter.sendMessage(service, "me", mimeMessage);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static String xmlAsString(Document doc) throws TransformerException {
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(doc), new StreamResult(writer));
		String output = writer.getBuffer().toString().replaceAll("\n|\r", "");

		return output;
	}

	// TODO 1 - generisi tajni (session) kljuc
	private static SecretKey generateSessionKey() throws NoSuchAlgorithmException, NoSuchPaddingException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 
		SecretKey secretKey = keyGen.generateKey();
		return secretKey;
	}

	// TODO 2 - iz sertifikata korisnika B izvuci njegov javni kljc
	private static PublicKey getPublicKey() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keyStore = KeyStore.getInstance("JKS", "SUN");
		
		BufferedInputStream in = new BufferedInputStream(
					new FileInputStream("./data/user_b.jks"));
		keyStore.load(in, "123".toCharArray());
		System.out.println("Cita se Sertifikat...");
		System.out.println("Ucitani sertifikat:");
		cert = keyStore.getCertificate("user_b");
		PublicKey  publicKey = cert.getPublicKey();
		return publicKey;
	}
}
