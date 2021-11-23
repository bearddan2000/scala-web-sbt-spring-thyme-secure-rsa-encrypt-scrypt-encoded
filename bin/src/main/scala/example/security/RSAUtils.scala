package example.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

object RSAUtils {

  val RSA = "RSA";

  // Generating public & private keys
  // using RSA algorithm.
  def generateRSAKeyPair(): KeyPair =
  {
      val secureRandom = new SecureRandom();
      val keyPairGenerator = KeyPairGenerator.getInstance(RSA);

      keyPairGenerator.initialize(2048, secureRandom);

      val keypair = keyPairGenerator.generateKeyPair();

      println("The Public Key is: " + DatatypeConverter.printHexBinary(keypair.getPublic().getEncoded()));

      println("The Private Key is: " + DatatypeConverter.printHexBinary(keypair.getPrivate().getEncoded()));

      return keypair;
  }

  // Encryption function which converts
  // the plainText into a cipherText
  // using private Key.
  def encrypt(plainText: String, keypair: KeyPair): Array[Byte] =
  {

    val privateKey = keypair.getPrivate();

    val cipher = Cipher.getInstance(RSA);

    cipher.init(Cipher.ENCRYPT_MODE, privateKey);

    val cipherText = cipher.doFinal(plainText.getBytes());

    print("The Encrypted Text is: ");

    val rsaText = DatatypeConverter.printHexBinary(cipherText);

    println(rsaText);

    println("The Encrypted Text length is: %d".format(rsaText.length()));

    return GZIPCompression.compress(rsaText);
  }

  // Decryption function which converts
  // the ciphertext back to the
  // original plaintext.
  def decrypt(cipherText: Array[Byte], keypair: KeyPair): String =
  {

    val dcompress = GZIPCompression.decompress(cipherText).getBytes();

    val publicKey = keypair.getPublic();

    val cipher = Cipher.getInstance(RSA);

      cipher.init(Cipher.DECRYPT_MODE, publicKey);

      val result = cipher.doFinal(dcompress);

      val rsaText = new String(result);

      println("The Decrypted text is: " + rsaText);

      return rsaText;
  }

}
