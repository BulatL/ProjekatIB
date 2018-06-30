package app;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;


import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.XMLCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import keystore.KeyStoreReader;
import model.keystore.IssuerData;
import support.MailHelper;
import support.MailReader;
import util.Base64;

public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	private static Certificate cert = null;
	
	//private static final String KEY_FILE = "./data/session.key";
	
	static {
		//staticka inicijalizacija
        Security.addProvider(new BouncyCastleProvider());
        org.apache.xml.security.Init.init();
	}
	
	public static void main(String[] args) throws Exception {
        // Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
        
        //Izlistavanje prvih PAGE_SIZE mail-ova prve stranice.
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
        
        //odabir mail-a od strane korisnika
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
		MimeMessage chosenMessage = mimeMessages.get(answer);
	    
        //izvlacenje teksta mail-a koji je trenutno u obliku stringa
		String xmlAsString = MailHelper.getText(chosenMessage);
		
		//kreiranje XML dokumenta na osnovu stringa
		Document doc = createXMlDocument(xmlAsString);
		
		// citanje keystore-a kako bi se izvukao sertifikat primaoca
		// i kako bi se dobio njegov tajni kljuc
		PrivateKey prvateKey = getPrivateKey();
					
		//desifrovanje tajnog (session) kljuca pomocu privatnog kljuca
		XMLCipher xmlCipher = XMLCipher.getInstance();
		xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
		
		//TODO 2 
		//postavlja se kljuc za dekriptovanje tajnog kljuca
		xmlCipher.setKEK(prvateKey);
		
		//TODO 3 trazi se prvi EncryptedData element i izvrsi dekriptovanje
		NodeList encDataList = doc.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData");
		Element encData = (Element) encDataList.item(0);
		
		//dekriptuje se
		//pri cemu se prvo dekriptuje tajni kljuc, pa onda njime podaci
		xmlCipher.doFinal(doc, encData); 
		
		System.out.println("Body text: " + doc.getElementsByTagName("mail").item(0).getTextContent());
		
	}
	
	private static String xmlAsString(Document doc) throws TransformerException{
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(doc), new StreamResult(writer));
		String output = writer.getBuffer().toString().replaceAll("\n|\r", "");
		
		return output;
	}
	
	private static Document createXMlDocument(String xmlAsString){
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();  
		factory.setNamespaceAware(true);
		DocumentBuilder builder;  
		Document doc = null;
		try {  
		    builder = factory.newDocumentBuilder();  
		    doc = builder.parse(new InputSource(new StringReader(xmlAsString)));  
		} catch (Exception e) {  
		    e.printStackTrace();  
		} 
		return doc;
	}
	
	// TODO 1 - iz sertifikata korisnika B izvuci njegov tajni kljc 
	private static PrivateKey getPrivateKey() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
		KeyStore keyStore = KeyStore.getInstance("JKS", "SUN");
		//ucitavanje keyStore
		BufferedInputStream in = new BufferedInputStream(new FileInputStream("./data/user_b.jks"));
		keyStore.load(in, "123".toCharArray());
		
		if(keyStore.isKeyEntry("user_b")) {
			PrivateKey privateKey = (PrivateKey) keyStore.getKey("user_b", "123".toCharArray());
			return privateKey;
		}
		else
			return null;
	}
}
