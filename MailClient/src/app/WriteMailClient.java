package app;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.internet.MimeMessage;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.google.api.services.gmail.Gmail;

import support.MailHelper;
import support.MailWritter;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;

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
			/*System.out.println("Insert a reciever:");
			BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
			String reciever = reader.readLine();

			System.out.println("Insert a subject:");
			String subject = reader.readLine();

			System.out.println("Insert body:");
			String body = reader.readLine();*/
			String reciever = "luka.serdar.lb@gmail.com";
			String subject = "ddddd";
			String body = "bbbb";

			// generisanje tajnog (session) kljuca
			SecretKey secretKey = generateSessionKey();
			
			String encryptedXml = encryptDoc(secretKey,subject,body);
			
			String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
			Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
			
			byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
			System.out.println("Kriptovan subject: " + ciphersubjectStr);

			// Slanje poruke
			MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, encryptedXml);
			MailWritter.sendMessage(service, "me", mimeMessage);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static String encryptDoc(SecretKey secretKey,String subject, String body) {
		try {
			// kreiraj xml dokument
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
	
			Document doc = docBuilder.newDocument();
			Element rootElement = doc.createElement("mail");
			
			Element sub = doc.createElement("sub");
			Element mailBody = doc.createElement("mailBody");
	
			doc.appendChild(rootElement);
			rootElement.appendChild(sub);
			rootElement.appendChild(mailBody);
			sub.setTextContent(subject);
			mailBody.setTextContent(body);	
	
			// dokument pre enkripcije
			String xml = xmlAsString(doc);
			System.out.println("Mail pre enkripcije: " + xml);
	
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
	
			//potpisivanje dokumenta
			WriteMailClient sign = new WriteMailClient();
			sign.signingDocument(doc);
			
			String encryptedXml = xmlAsString(doc);
			System.out.println("Mail posle enkripcije: " + encryptedXml);
		
			return encryptedXml;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";
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
		
		System.out.println("Insert your jks file name:");
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		String userAJKS = reader.readLine();
		
		System.out.println("Insert your password for jks:");
		String userA_password = reader.readLine();
		
		
		System.out.println("Insert reciver certificate alias:");
		String userB_Certificate = reader.readLine();
		
		BufferedInputStream in = new BufferedInputStream(
					new FileInputStream("./data/"+userAJKS));
		keyStore.load(in, userA_password.toCharArray());
		System.out.println("Cita se Sertifikat...");
		System.out.println("Ucitani sertifikat:");
		cert = keyStore.getCertificate(userB_Certificate);
		//cert = keyStore.getCertificate("user_b");
		PublicKey  publicKey = cert.getPublicKey();
		return publicKey;
	}
	
	private Document signDocument(Document doc, PrivateKey privateKey, X509Certificate cert) {
		try {
			Element rootEl = doc.getDocumentElement();
			
			//kreira se signature objekat
			XMLSignature sig = new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
			//kreiraju se transformacije nad dokumentom
			Transforms transforms = new Transforms(doc);
			    
			//iz potpisa uklanja Signature element
			//Ovo je potrebno za enveloped tip po specifikaciji
			transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
			//normalizacija
			transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
			    
			//potpisuje se citav dokument (URI "")
			sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
			    
			//U KeyInfo se postavalja Javni kljuc samostalno i citav sertifikat
			sig.addKeyInfo(cert.getPublicKey());
			sig.addKeyInfo((X509Certificate) cert);
			    
			//poptis je child root elementa
			rootEl.appendChild(sig.getElement());
			//potpisivanje
			sig.sign(privateKey);
			
			return doc;
	    } catch (TransformationException e) {
			e.printStackTrace();
			return null;
		} catch (XMLSignatureException e) {
			e.printStackTrace();
			return null;
		} catch (DOMException e) {
			e.printStackTrace();
			return null;
		} catch (XMLSecurityException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private static PrivateKey getPrivateKey(){
		try {
			KeyStore keyStore = KeyStore.getInstance("JKS", "SUN");
			//ucitavanje keyStore
			BufferedInputStream in = new BufferedInputStream(new FileInputStream("./data/user_a.jks"));
			keyStore.load(in, "123".toCharArray());
			
			if(keyStore.isKeyEntry("user_a")) {
				PrivateKey privateKey = (PrivateKey) keyStore.getKey("user_a", "123".toCharArray());
				return privateKey;
			}
			else
				return null;
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			return null;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (CertificateException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
			return null;
		} 
	}
	
	private X509Certificate getCertificate() {
		try {
			//kreiramo instancu KeyStore
			KeyStore ks = KeyStore.getInstance("JKS", "SUN");
			//ucitavamo podatke
			BufferedInputStream in = new BufferedInputStream(new FileInputStream("./data/user_b.jks"));
			ks.load(in, "123".toCharArray());
			
			if(ks.isKeyEntry("user_b")) {
				X509Certificate cert = (X509Certificate) ks.getCertificate("user_a");
				return cert;
				
			}
			else
				return null;
			
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			return null;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (CertificateException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} 
	}
	
	private void signingDocument(Document doc){
		PrivateKey privateKey = getPrivateKey();
		X509Certificate cert = getCertificate();
		System.out.println("Signing....");
		doc = signDocument(doc, privateKey, cert);
	}
}
