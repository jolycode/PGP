package security_project;
import java.io.*;
import java.util.*;
import java.math.*;
import java.security.*;https://github.com/jolycode/PGP/blob/main/Client.java
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.*;

import java.util.zip.GZIPOutputStream;
public class Client {
    private static DataOutputStream dataOutputStream = null;
    private static DataInputStream dataInputStream = null;
    static Cipher encryptCipher, decryptCipher;
    int keySize = 2048;
    public static void main(String[] args) throws IOException {
    	Scanner sc = new Scanner(System.in);
    	String ip="127.0.0.1";int port=990;
    	System.out.println("Enter the name of the file to be sent");
    	String fileName = sc.nextLine(); 
    	String path="C:/Users/danil/CSE_ALL/439sec/"+fileName;
        try(Socket socket = new Socket(ip,port)) {
            dataInputStream = new DataInputStream(socket.getInputStream());
            dataOutputStream = new DataOutputStream(socket.getOutputStream());   
            PGP(path); //path
            dataInputStream.close();
            System.out.println("File is sent");
        }catch (Exception e){
            e.printStackTrace();
        }
    }
    public static void PGP(String path) throws Exception {
        String input = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
        //Generating server keys
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);  
        KeyPairGenerator keyPairGenerator2 = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator2.initialize(2048);//Generating client keys
        KeyPair keyPair1=keyPairGenerator.genKeyPair();
        KeyPair keyPair2=keyPairGenerator.genKeyPair();
        PrivateKey senderPrivateKey =  keyPair1.getPrivate();//
        PublicKey receiverPubKey =  keyPair2.getPublic();// get server public key
        try (FileOutputStream out = new FileOutputStream("private.key")) {
            out.write(keyPair2.getPrivate().getEncoded());
        }
        try (FileOutputStream out = new FileOutputStream("public.pub")) {
            out.write(keyPair1.getPublic().getEncoded() );
        }
        String checksum;
    	//Generating SHA-512 hash of original message
        MessageDigest digest=MessageDigest.getInstance("SHA-512");
        digest.reset();
        digest.update(input.getBytes("utf8"));
        checksum = String.format("%040x", new BigInteger(1, digest.digest()));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,senderPrivateKey);
        byte[] utf8 =cipher.doFinal(checksum.getBytes("UTF-8"));
        //Encrypt the message hash with sender private keys -> Digital Signature
        String encryptedPrivateHash= Base64.getEncoder().encodeToString(utf8);
      //Append original message and encrypted hash
        String beforeZip[]={input,encryptedPrivateHash};
        String afterZip[]=new String[beforeZip.length];
        for(int i=0;i<beforeZip.length;i++){
            ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream(beforeZip[i].length());
            GZIPOutputStream gZip=new GZIPOutputStream(byteArrayOutputStream);
            gZip.write(beforeZip[i].getBytes());
            gZip.close();
            byte[] compressed=byteArrayOutputStream.toByteArray();
            byteArrayOutputStream.close();
            afterZip[i]=Base64.getEncoder().encodeToString(compressed);
        }
        //Encrypt zipstring with DES
        SecretKey key=KeyGenerator.getInstance("DES").generateKey();
        String afterZipDES[]=new String[afterZip.length+1];
        for(int i=0;i<afterZip.length;i++){
            encryptCipher = Cipher.getInstance("DES");
            encryptCipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] utf8str =afterZip[i].getBytes("UTF8");
            byte[] encrypted = encryptCipher.doFinal(utf8str);
            afterZipDES[i]=Base64.getEncoder().encodeToString(encrypted);
        }
      //Encrypt DES key with Receiver Public Key using RSA
            String encodedKey=Base64.getEncoder().encodeToString(key.getEncoded());
            Cipher cipher2 = Cipher.getInstance("RSA");
            cipher2.init(Cipher.ENCRYPT_MODE, receiverPubKey);  
            byte[] utf8new2 = cipher2.doFinal(encodedKey.getBytes("UTF-8"));
          //SecretKey is base64 encoded 
            String encryptedKey=Base64.getEncoder().encodeToString(utf8new2);
          //Decrypting DES key with Receiver Private Key using RSA
            afterZipDES[2]=encryptedKey;
            String messageToServer[]=afterZipDES;
            sendFile(messageToServer);
    }
    private static void sendFile(String array[]) throws Exception{
        for(int i = 0 ; i < 3 ; i++){
            System.out.println(array[i]);//messageToServer --> afterZipDES
        }
        byte[] data=array[0].getBytes("UTF-8");
        dataOutputStream.writeInt(data.length);
        dataOutputStream.write(data);
        byte[] hash=array[1].getBytes("UTF-8"); 
        dataOutputStream.writeInt(hash.length);
        dataOutputStream.write(hash);// send hash
        byte[] key=array[2].getBytes("UTF-8"); 
        dataOutputStream.writeInt(key.length);
        dataOutputStream.write(key); 
    } 
}


