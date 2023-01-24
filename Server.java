package security_project;
import java.io.*;
import java.util.*;
import java.net.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.zip.GZIPInputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
public class Server {
	 static Cipher ecipher, dcipher;
	    private static DataOutputStream dataOutputStream = null;
	    private static DataInputStream dataInputStream = null;
	    public static void main(String[] args) {
	    	int port=990;
	        try(ServerSocket serverSocket = new ServerSocket(port)){
	            System.out.println("Listenning on port:"+port);
	            Socket clientSocket = serverSocket.accept();
	            System.out.println(" Client connected: "+clientSocket);
	            dataInputStream = new DataInputStream(clientSocket.getInputStream());
	            dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());     
	            /*receiving file                      */
		        int length=dataInputStream.readInt();
		        byte[] data_=new byte[length];
		        dataInputStream.readFully(data_);
		        String data =new String(data_,"UTF-8");
		        System.out.println("data:"+data+"\n\n");
		        int length2=dataInputStream.readInt();
		        byte[] hash_=new byte[length2];
		        dataInputStream.readFully(hash_);
		        String hash=new String(hash_,"UTF-8");
		        System.out.println("Hash:"+hash+"\n\n");
		        int length3=dataInputStream.readInt();
		        byte[] key_=new byte[length3];
		        dataInputStream.readFully(key_);
		        String key=new String(key_,"UTF-8");
		        PGP(data,hash,key);   
	            /*received            */	          
	            dataInputStream.close();
	            dataOutputStream.close();
	            clientSocket.close();
	        } catch (Exception e){
	            e.printStackTrace();
	        }
	    }
	    private static void PGP(String data, String hash, String key) throws Exception {
	        String[] message={data,hash,key};
	    	//Receiver receives the message as secret key encrypted with receiver pub key
	        byte[] bytes = Files.readAllBytes(Paths.get("public.pub"));
	    	//Receiver decrypts the  with  privatekey
	        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
	        KeyFactory kf = KeyFactory.getInstance("RSA");
	        PublicKey publicKey = kf.generatePublic(ks);
	        byte[] bytes2 = Files.readAllBytes(Paths.get("private.key"));
	        PKCS8EncodedKeySpec ks2 = new PKCS8EncodedKeySpec(bytes2);
	        KeyFactory kf2 = KeyFactory.getInstance("RSA");
	        PrivateKey privateKey = kf2.generatePrivate(ks2);
	        //Key after decryption is in base64 encoded form
	        byte[] encrypted=Base64.getDecoder().decode(key);
	        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	        cipher.init(Cipher.DECRYPT_MODE,privateKey);
			byte[] utf8 = cipher.doFinal(encrypted);
	        String eRecevierSecretKey=new String(utf8,"UTF8");
	        byte[] dReceiverSecretKey = Base64.getDecoder().decode(eRecevierSecretKey);
	        SecretKey originalKey = new SecretKeySpec(dReceiverSecretKey, 0, dReceiverSecretKey.length, "DES");
	        //Decrypt the rest of the message in messagetoreceiver with SecretKey originalKey
			String receiverdEcryptedMessage[] = new String[message.length-1];
			
	        dcipher = Cipher.getInstance("DES");
		    dcipher.init(Cipher.DECRYPT_MODE, originalKey);
	        for(int i=0;i<message.length-1;i++){
	        // Decode base64 to get bytes
	            byte[] dec=Base64.getDecoder().decode(message[i]);
	            byte[] utf8_ = dcipher.doFinal(dec);  
	         // Decode using utf-8
	            message[i]= new String(utf8_,"UTF8");
	        } 
	        String unzippedString[]=new String[receiverdEcryptedMessage.length]; //Unziping
	        File fout = new File("C:/Users/danil/CSE_ALL/439sec/server_output/new.txt"); //new file path
	        FileOutputStream fos = new FileOutputStream(fout);
	        for(int i=0;i<unzippedString.length;i++){//compress
	            byte[] compressed=Base64.getDecoder().decode(message[i]);
	        	ByteArrayInputStream bis = new ByteArrayInputStream(compressed);
	            GZIPInputStream gis = new GZIPInputStream(bis);
	            BufferedReader br = new BufferedReader(new InputStreamReader(gis, "UTF-8"));
	            StringBuilder sb = new StringBuilder();
	            String line;
	            while((line = br.readLine()) != null) {
	                if(i==0){
	                    fos.write(line.getBytes("utf8"));
	                    fos.write(10);
	                }
	                sb.append(line);
	            }
	            fos.close();
	            br.close();
	            gis.close();
	            bis.close();
	            unzippedString[i]=sb.toString();  
	         }
	         byte[] encrypted2=Base64.getDecoder().decode(unzippedString[1]);
	         cipher.init(Cipher.DECRYPT_MODE,publicKey);
	         byte[] utf8_2 = cipher.doFinal(encrypted2);
	       //Message has been received and is in unzipstring but check the digital signature of the sender i.e. verify the hash with senderpubkey
	      //decrypting the encrypted hash in unzipstring with sender pub key
	         String receivedHash=new String(utf8_2,"UTF8");
	     	//Calculating SHA512 at receiver side of message
	         MessageDigest digest = MessageDigest.getInstance("SHA-512");
			 digest.reset();
			 digest.update(unzippedString[0].getBytes("utf8"));
			 String calculatedHash = String.format("%040x", new BigInteger(1, digest.digest()));
	         if(receivedHash.equalsIgnoreCase(calculatedHash)) { //authentication
	            System.out.println("File is Received.\n");
	         }
	    }
}
