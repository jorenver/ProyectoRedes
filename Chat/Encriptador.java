 import java.security.Key;
 
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
 
/**
 * Ejemplo de encriptado y desencriptado con algoritmo AES.
 * Se apoya en RSAAsymetricCrypto.java para salvar en fichero
 * o recuperar la clave de encriptación.
 * 
 * @author Chuidiang
 *
 */

public class Encriptador {
      public Key key;
      public Cipher c;

      public Encriptador(){
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            key = keyGenerator.generateKey();
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
      }

 
   public static void main(String[] args) throws Exception {
 
      // Texto a encriptar
      String texto = "Este es el texto que queremos encriptar";
 
      // Se obtiene un cifrador AES
      
 
      // Se inicializa para encriptacion y se encripta el texto,
      // que debemos pasar como bytes.
      c.init(Cipher.ENCRYPT_MODE, key);
      byte[] encriptado = c.doFinal(texto.getBytes());
 
      // Se escribe byte a byte en hexadecimal el texto
      // encriptado para ver su pinta.
      for (byte b : encriptado) {
         System.out.print(Integer.toHexString(0xFF & b));
      }
      System.out.println();
 
      // Se iniciliza el cifrador para desencriptar, con la
      // misma clave y se desencripta
      c.init(Cipher.DECRYPT_MODE, key);
      byte[] desencriptado = c.doFinal(encriptado);
 
      // Texto obtenido, igual al original.
      System.out.println(new String(desencriptado));
   }
}