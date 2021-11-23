package example.security;

import java.security.KeyPair;
import javax.xml.bind.DatatypeConverter;

import org.springframework.security.crypto.password.PasswordEncoder;

class RSAPasswordEncoder
  extends org.springframework.security.crypto.scrypt.SCryptPasswordEncoder
  with PasswordEncoder {

    val keypair: KeyPair =  RSAUtils.generateRSAKeyPair();

    override def encode(rawPassword: CharSequence): String = {
      try {
        val plainText = rawPassword.toString();
        val rsaText = RSAUtils.encrypt(plainText, this.keypair);
        return super.encode(DatatypeConverter.printHexBinary(rsaText));
      } catch{
        case e: Exception => {}
      }
      return super.encode(rawPassword);
    }

    override def matches(rawPassword: CharSequence, encodedPassword: String): Boolean =
    {
     try {
        val plainText = rawPassword.toString();
        val rsaText = RSAUtils.encrypt(plainText, this.keypair);
        val plain = DatatypeConverter.printHexBinary(rsaText);
       return super.matches(plain, encodedPassword);
       } catch{
         case e: Exception => {}
       }
     return false;
    }
}
