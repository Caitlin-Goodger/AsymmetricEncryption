import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private KeyPair kp;
    private PublicKey clientPublicKey;
    private String encrpytion = "RSA/ECB/PKCS1Padding";
    private String signing = "SHA256withRSA";

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) throws  NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException{
        serverSocket = new ServerSocket(port);
        clientSocket = serverSocket.accept();
        out = new DataOutputStream(clientSocket.getOutputStream());
        in = new DataInputStream(clientSocket.getInputStream());
        byte[] data = new byte[256];
        byte[] insignatureBytes = new byte[256];
        int numBytes;
        while ((numBytes = in.read(data)) != -1) {
            // Decrypt data using the server's private key
            in.read(insignatureBytes);
            Cipher cipher = Cipher.getInstance(encrpytion);
            cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            byte[] decryptedBytes = cipher.doFinal(data);
            String decOut = new String(decryptedBytes, "UTF-8");
            System.out.println("Server received cleartext "+decOut);

            //Authenticate the message by using the client's public key
            Signature insig = Signature.getInstance(signing);
            insig.initVerify(clientPublicKey);
            insig.update(decryptedBytes);
            boolean signatureValid = insig.verify(insignatureBytes);

            if(signatureValid) {
                System.out.println("Signature Valid");
            } else {
                System.out.println("Signature Invalid");
                throw new SignatureException();
            }



            //Encrypt the message using the client's public key
            cipher = Cipher.getInstance(encrpytion);
            cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
            byte[] cipherBytes = cipher.doFinal(decryptedBytes);

            Base64.Encoder en = Base64.getEncoder();
            System.out.println("Server sending ciphertext "+ new String(en.encode(cipherBytes)));

            //Sign the message using the server's public key
            Signature sig = Signature.getInstance(signing);
            sig.initSign(kp.getPrivate());
            sig.update(decryptedBytes);
            byte[] signatureBytes = sig.sign();

            //Send the encrypted message and the signature to the client
            out.write(cipherBytes);
            out.write(signatureBytes);
            //out.write(data);
            out.flush();
        }
        stop();


    }

    /**
     * Close the streams and sockets.
     *
     */
    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    /**
     * Generate a public and private key pair
     */
    public void generateKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kp = kpg.generateKeyPair(); //The same as genKeyPair

        PublicKey publicKey = kp.getPublic();
        Base64.Encoder en = Base64.getEncoder();
        String ePub = en.encodeToString(publicKey.getEncoded());
        System.out.println("Public key is " + ePub);
    }

    /**
     * Read in the Client Key that the user has provided
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public void getClientKey() throws NoSuchAlgorithmException, InvalidKeySpecException{
        System.out.println("Please enter the clients's public key below:");
        Scanner sc = new Scanner(System.in);
        String ePub = sc.next();
        sc.close();

        //Create a client public key using the string provided
        Base64.Decoder de = Base64.getDecoder();
        byte[] key = de.decode(ePub);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        clientPublicKey = keyFactory.generatePublic(pubKeySpec);

    }

    public static void main(String[] args) {
        EchoServer server = new EchoServer();
        try {
            server.generateKeys();
            server.getClientKey();
            System.out.println("Waiting to complete Exchange");
            server.start(4444);
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
        } catch ( BadPaddingException e) {
            System.out.println("There isn't enough padding for this encryption. Please try again.");
        } catch (SignatureException e) {
            System.out.println("The signature doesn't match. This message may not be from the right person");
        } catch (IOException e) {
            System.out.println("There is a issue sending this message. Please try again");
        } catch (IllegalArgumentException e) {
            System.out.println("A Key should be longer than 2 bytes. Please try again with a valid key");
        }
    }

}



