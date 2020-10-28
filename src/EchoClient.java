import com.sun.org.apache.xml.internal.security.signature.InvalidSignatureValueException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private KeyPair kp;
    private PublicKey serverPublicKey;
    private String encrpytion = "RSA/ECB/PKCS1Padding";
    private String signing = "SHA256withRSA";

    /**
     * Setup the two way streams.
     *
     * @param ip the address of the server
     * @param port port used by the server
     *
     */
    public void startConnection(String ip, int port){
        try {
            clientSocket = new Socket(ip, port);
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            System.out.println("Error when initializing connection");
        }
    }

    /**
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public String sendMessage(String msg) throws  NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException {
        System.out.println("Client sending cleartext "+msg);
        byte[] data = msg.getBytes("UTF-8");

        //Encrypt the message using the server's public key
        Cipher cipher = Cipher.getInstance(encrpytion);
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] cipherBytes = cipher.doFinal(data);

        //Sign using the client's private key
        Signature sig = Signature.getInstance(signing);
        sig.initSign(kp.getPrivate());
        sig.update(data);
        byte[] signatureBytes = sig.sign();


        Base64.Encoder en = Base64.getEncoder();
        System.out.println("Client sending ciphertext "+ new String(en.encode(cipherBytes)));
        //Send the encrypted message and the signature to the server
        out.write(cipherBytes);
        out.write(signatureBytes);
        out.flush();

        //Decryption
        byte[] incoming = new byte[256];
        byte [] insignatureBytes = new byte[256];
        in.read(incoming);
        in.read(insignatureBytes);

        //Decrypt the message using the client's private key
        cipher = Cipher.getInstance(encrpytion);
        cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] decryptedBytes = cipher.doFinal(incoming);
        String decOut = new String(decryptedBytes, "UTF-8");
        System.out.println("Client received cleartext "+decOut);

        //Authenticate the message using the server's public key
        Signature insig = Signature.getInstance(signing);
        insig.initVerify(serverPublicKey);
        insig.update(decryptedBytes);
        boolean signatureValid = insig.verify(insignatureBytes);

        if(signatureValid) {
            System.out.println("Signature Valid");
        } else {
            System.out.println("Signature Invalid");
            throw new SignatureException();
        }

        return decOut;
    }

    /**
     * Close down our streams.
     *
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("error when closing");
        }
    }

    /**
     * Generate a public and private key pair for the server
     */
    public  void generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kp = kpg.generateKeyPair(); //The same as genKeyPair
        PublicKey publicKey = kp.getPublic();
        Base64.Encoder en = Base64.getEncoder();
        String ePub = en.encodeToString(publicKey.getEncoded());
        System.out.println("Client Public key is " + ePub);

    }

    /**
     * Read in the server key that the user has provided.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public void getServerKey() throws NoSuchAlgorithmException, InvalidKeySpecException{
        System.out.println("Please enter the servers's public key below:");
        Scanner sc = new Scanner(System.in);
        String ePub = sc.next();
        sc.close();

        //Create the server's public key from the string provided
        Base64.Decoder de = Base64.getDecoder();
        byte[] key = de.decode(ePub);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        serverPublicKey = keyFactory.generatePublic(pubKeySpec);


    }

    public static void main(String[] args){
        EchoClient client = new EchoClient();

        try {
            client.generateKeys();
            client.getServerKey();

            System.out.println("Keys exchanged");

            client.startConnection("127.0.0.1", 4444);
            client.sendMessage("12345678");
            client.sendMessage("ABCDEFGH");
            client.sendMessage("87654321");
            client.sendMessage("HGFEDCBA");

            client.stopConnection();
        } catch (NoSuchAlgorithmException e){
            System.out.println("That algorithm can't be found. Please try again");
        } catch (InvalidKeySpecException e) {
            System.out.println("That isn't a valid key. Please enter a valid key");
        } catch (NoSuchPaddingException e) {
            System.out.println("There isn't enough padding for this encryption. Please try again");
        } catch (InvalidKeyException e) {
            System.out.println("That isn't a valid key. Please try again and enter a valid key");
        } catch (IllegalBlockSizeException e) {
            System.out.println("There is not enough space for this cipher. Please try again");
        } catch (BadPaddingException e) {
            System.out.println("There isn't enough padding for this encryption. Please try again.");
        } catch (SignatureException e) {
            System.out.println("The signature doesn't match. This message may not be from the right person");
        } catch (IOException e) {
            System.out.println("There is a issue sending this message. Please try again");
        } catch (IllegalArgumentException e) {
            System.out.println("A Key should be longer than 2 bytes. Please try again with a valid key");
        } catch (NullPointerException e) {
            System.out.println("Please start the Server before the Client. Please give the public key to the server first");
        }
    }
}
