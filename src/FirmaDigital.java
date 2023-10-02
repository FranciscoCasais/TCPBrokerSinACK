import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
public interface FirmaDigital {
    static Mensaje obtenerObjetoMensajeAES(RSA clavesEmisor,SecretKey claveSimetrica,String comando) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String mensaje1=obtenerMensaje1(clavesEmisor,comando);
        String mensaje2=obtenerMensaje2AES(claveSimetrica,comando);
        return new Mensaje(mensaje1,mensaje2);
    }
    static Mensaje obtenerObjetoMensajeRSA(RSA clavePublicaReceptor, RSA clavesEmisor, String comando) throws NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {
        String mensaje1=obtenerMensaje1(clavesEmisor,comando);
        String mensaje2=obtenerMensaje2RSA(clavePublicaReceptor,comando);
        return new Mensaje(mensaje1,mensaje2);
    }
    static String obtenerMensaje1(RSA clavesEmisor, String mensaje) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        // hashea el mensaje
        MessageDigest md=MessageDigest.getInstance("SHA-256");
        md.update(mensaje.getBytes());
        byte[] hashBytes=md.digest();
        StringBuilder hashHex=new StringBuilder();
        for(byte hashByte:hashBytes) {
            String hex=Integer.toHexString(0xff & hashByte);
            if(hex.length()==1) hashHex.append('0');
            hashHex.append(hex);
        }

        // lo encripta con la clave privada del emisor
        return clavesEmisor.encriptarClavePrivada(hashHex.toString());

    }
    static String obtenerMensaje2AES(SecretKey claveSimetrica,String mensaje) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, claveSimetrica);
        byte[] encryptedData = cipher.doFinal(mensaje.getBytes());
        return RSA.bytesToString(encryptedData);
    }
    static String obtenerMensaje2RSA(RSA clavePublicaReceptor, String mensaje) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        // lo encripta con la clave publica del receptor
        return clavePublicaReceptor.encriptarClavePublica(mensaje);
    }
    static String obtenerTopico1(String comando) {
        String topico="";
        int i=1;
        while(comando.charAt(i)!=' ') {
            topico+=comando.charAt(i);
            i++;
        }
        return topico;
    }
    static String obtenerTopico2(String comando) {
        String topico="";
        boolean entrar=false;
        for(int i=0;i<comando.length();i++) {
            if(entrar) topico+=comando.charAt(i);
            else if(comando.charAt(i)==' ') entrar=true;
        }
        return topico;
    }
    static String verificarFirmaDigitalAES(Object objetoRecibido,RSA clavePublicaEmisor,SecretKey claveSimetrica) throws MensajeModificadoException, ObjetoTipoIncorrectoException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        if(objetoRecibido instanceof Mensaje) {
            Mensaje mensajeRecibido=(Mensaje) objetoRecibido;

            // desencripta el mensaje 1 hasheado con la clave pública del emisor
            String mensaje1Desencriptado=clavePublicaEmisor.desencriptarClavePublica(mensajeRecibido.getMensaje1());

            // desencripta el mensaje 2 con la clave simetrica
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, claveSimetrica);
            byte[] decryptedData = cipher.doFinal(RSA.stringToBytes(mensajeRecibido.getMensaje2()));
            String mensaje2Desencriptado = new String(decryptedData);

            // hashea el mensaje 2
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(mensaje2Desencriptado.getBytes());
            byte[] hashBytes = md.digest();
            StringBuilder hashHex = new StringBuilder();
            for (byte hashByte : hashBytes) {
                String hex = Integer.toHexString(0xff & hashByte);
                if (hex.length() == 1) {
                    hashHex.append('0');
                }
                hashHex.append(hex);
            }
            String mensaje2Hasheado=hashHex.toString();

            // los compara
            if(mensaje1Desencriptado.equals(mensaje2Hasheado)) return mensaje2Desencriptado;
            else throw new MensajeModificadoException("Error: la verificación de firma digital falló.");
        } else throw new ObjetoTipoIncorrectoException("Error: el objeto transferido no es de tipo Mensaje.");
    }
    static String verificarFirmaDigitalRSA(Object objetoRecibido, RSA clavePublicaEmisor, RSA clavesReceptor) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, MensajeModificadoException, ObjetoTipoIncorrectoException {

        if(objetoRecibido instanceof Mensaje) {
            Mensaje mensajeRecibido=(Mensaje) objetoRecibido;

            // desencripta el mensaje 1 hasheado con la clave pública del emisor
            String mensaje1Desencriptado=clavePublicaEmisor.desencriptarClavePublica(mensajeRecibido.getMensaje1());

            // desencripta el mensaje 2 con la clave privada del receptor
            String mensaje2Desencriptado=clavesReceptor.desencriptarClavePrivada(mensajeRecibido.getMensaje2());

            // hashea el mensaje 2
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(mensaje2Desencriptado.getBytes());
            byte[] hashBytes = md.digest();
            StringBuilder hashHex = new StringBuilder();
            for (byte hashByte : hashBytes) {
                String hex = Integer.toHexString(0xff & hashByte);
                if (hex.length() == 1) {
                    hashHex.append('0');
                }
                hashHex.append(hex);
            }
            String mensaje2Hasheado=hashHex.toString();

            // los compara
            if(mensaje1Desencriptado.equals(mensaje2Hasheado)) return mensaje2Desencriptado;
            else throw new MensajeModificadoException("Error: la verificación de firma digital falló.");
        } else throw new ObjetoTipoIncorrectoException("Error: el objeto transferido no es de tipo Mensaje.");
    }
}