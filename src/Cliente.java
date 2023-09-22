import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
public class Cliente extends Thread {
    private HashSet<String> topicosServidor,topicosSuscrito;
    private ObjectInputStream inputStream;
    private RSA clavesCliente,clavesServidor;
    private Socket conexion;
    public Cliente(HashSet<String> topicosServidor,HashSet<String> topicosSuscrito,ObjectInputStream inputStream,RSA clavesCliente,RSA clavesServidor,Socket conexion) {
        this.topicosServidor=topicosServidor;
        this.topicosSuscrito=topicosSuscrito;
        this.inputStream=inputStream;
        this.clavesCliente=clavesCliente;
        this.clavesServidor=clavesServidor;
        this.conexion=conexion;
    }
    public HashSet<String> getTopicosServidor() { return topicosServidor; }
    public HashSet<String> getTopicosSuscrito() { return topicosSuscrito; }
    public ObjectInputStream getInputStream() { return inputStream; }
    public RSA getClavesCliente() { return clavesCliente; }
    public RSA getClavesServidor() { return clavesServidor; }
    public Socket getConexion() { return conexion; }
    public void setTopicosServidor(HashSet<String> topicosServidor) { this.topicosServidor=topicosServidor; }
    public void setTopicosSuscrito(HashSet<String> topicosSuscrito) { this.topicosSuscrito=topicosSuscrito; }
    public void setInputStream(ObjectInputStream inputStream) { this.inputStream=inputStream; }
    public void setClavesCliente(RSA clavesCliente) { this.clavesCliente = clavesCliente; }
    public void setClavesServidor(RSA clavesServidor) { this.clavesServidor=clavesServidor; }
    public void setConexion(Socket conexion) { this.conexion=conexion; }
    /* public void run() {
        try {
            boolean terminar=false;
            do {
                // BufferedReader lector=new BufferedReader(new InputStreamReader(conexion.getInputStream()));
                // String mensaje=lector.readLine();
                // ObjectInputStream inputStream=new ObjectInputStream(conexion.getInputStream());
                Object mensaje=inputStream.readObject();
                if(mensaje instanceof Mensaje) {
                    Mensaje mensajeRecibido=(Mensaje) mensaje;
                    String mensajeRecibidoString=verificarFirmaDigital(clavesServidor,mensajeRecibido);
                    if(mensajeRecibidoString.charAt(0)=='/') { System.out.println(mensajeRecibidoString); }
                    else if(mensajeRecibidoString.equals("-fin")) {
                        // lector.close();
                        terminar=!terminar;
                    }
                }
            } while(!terminar);
            this.getConexion().close();
        } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | ClassNotFoundException e) { throw new RuntimeException(e); }
    } */
    public String obtenerMensaje1(String mensaje) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, BadPaddingException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {

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

        // lo encripta con la clave privada del cliente
        String mensaje1= getClavesCliente().encriptarClavePrivada(hashHex.toString());
        return mensaje1;

    }
    public String obtenerMensaje2(RSA rsaServidor,String mensaje) throws NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {

        // lo encripta con la clave publica del servidor
        String mensaje2=rsaServidor.encriptarClavePublica(mensaje);
        return mensaje2;

    }
    public Mensaje obtenerObjetoMensaje(RSA rsaServidor,String comando) throws NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {
        String mensaje1=this.obtenerMensaje1(comando);
        String mensaje2=this.obtenerMensaje2(rsaServidor,comando);
        Mensaje mensajeFinal=new Mensaje(mensaje1,mensaje2);
        return mensajeFinal;
    }
    public String verificarFirmaDigital(RSA rsaServidor,Mensaje mensajeRecibido) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // desencripta el mensaje 1 hasheado con la clave pública del cliente
        String mensaje1Desencriptado=rsaServidor.desencriptarClavePublica(mensajeRecibido.getMensaje1());

        // desencripta el mensaje 2 con la clave privada del servidor
        String mensaje2Desencriptado= getClavesCliente().desencriptarClavePrivada(mensajeRecibido.getMensaje2());

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
        else return null;
    }
    public boolean buscarTopico(ObjectInputStream inputStream,ObjectOutputStream outputStream,RSA rsaServidor,String comando) {
        String topico="";
        if(comando.charAt(0)=='@') {
            int i=1;
            while(comando.charAt(i)!=' ') {
                topico+=comando.charAt(i);
                i++;
            }
        } else {
            boolean entrar=false;
            for(int i=0;i<comando.length();i++) {
                if(entrar) { topico+=comando.charAt(i); }
                else if(comando.charAt(i)==' ') { entrar=!entrar; }
            }
        }
        if(topicosServidor.contains(topico)) { return true; }
        else {
            buscarTopicosServidor(inputStream,outputStream,rsaServidor,topico);
            return false;
        }
    }
    public void buscarTopicosServidor(ObjectInputStream inputStream,ObjectOutputStream outputStream,RSA rsaServidor,String topico) {
        try {
            // ObjectInputStream inputStream=new ObjectInputStream(conexion.getInputStream());
            // ObjectOutputStream outputStream=new ObjectOutputStream(conexion.getOutputStream());
            // PrintWriter impresor=new PrintWriter(conexion.getOutputStream(),true);
            String comando="-bt "+topico;
            // impresor.println(comando);
            // BufferedReader lector=new BufferedReader(new InputStreamReader(conexion.getInputStream()));
            // String respuesta=lector.readLine();
            Mensaje mensajeFinal=obtenerObjetoMensaje(rsaServidor,comando);
            outputStream.writeObject(mensajeFinal);
            // if(evaluarRespuesta(inputStream,rsaServidor)) return true;
            // else return false;
        } catch(IOException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeySpecException | InvalidKeyException | NoSuchProviderException | NoSuchPaddingException e) { throw new RuntimeException(e); }
    }
    public boolean evaluarRespuesta(ObjectInputStream inputStream,RSA rsaServidor) throws IOException, ClassNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        // MyObjectInputStream myInputStream=new MyObjectInputStream(conexion.getInputStream());
        Object mensaje=inputStream.readObject();
        // Object mensaje=myInputStream.readObject();
        if(mensaje instanceof Mensaje) {
            Mensaje mensajeRecibido=(Mensaje) mensaje;
            String respuesta=verificarFirmaDigital(rsaServidor,mensajeRecibido);
            if(respuesta.equals("0")) { return false; }
            else {
                this.setTopicosServidor(obtenerTopicos(mensaje,rsaServidor));
                return true;
            }
        }
        return false;
    }
    public boolean suscritoTopico(String comando) {
        int i=1;
        String topico="";
        while(comando.charAt(i)!=' ') {
            topico+=comando.charAt(i);
            i++;
        }
        if(getTopicosSuscrito().contains(topico)) return true;
        else return false;
    }
    public void suscribirDesuscribir(ObjectOutputStream outputStream,RSA rsaServidor,String comando) {
        try {
            boolean entrar=false;
            Mensaje mensajeFinal;
            // ObjectOutputStream outputStream = new ObjectOutputStream(conexion.getOutputStream());
            // PrintWriter impresor=new PrintWriter(conexion.getOutputStream(),true);
            String topico="";
            for(int i=0;i<comando.length();i++) {
                if(entrar) { topico+=comando.charAt(i); }
                else if(comando.charAt(i)==' ') { entrar=!entrar; }
            }
            if(comando.charAt(1)=='s' && this.topicosSuscrito.contains(topico)) { System.out.println("Ya está suscrito al tópico."); }
            else if(comando.charAt(1)=='s') {
                this.getTopicosSuscrito().add(topico);
                mensajeFinal=obtenerObjetoMensaje(rsaServidor,comando);
                outputStream.writeObject(mensajeFinal);
                // impresor.println(comando);
                System.out.println("Se le suscribió al tópico \""+topico+"\".");
            }
            else if(comando.charAt(1)=='d' && !this.topicosSuscrito.contains(topico)) { System.out.println("No está suscrito al tópico."); }
            else {
                this.getTopicosSuscrito().remove(topico);
                mensajeFinal=obtenerObjetoMensaje(rsaServidor,comando);
                outputStream.writeObject(mensajeFinal);
                // impresor.println(comando);
                System.out.println("Se le desuscribió del tópico \""+topico+"\".");
            }
        } catch(IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeySpecException | InvalidKeyException | NoSuchProviderException e) { throw new RuntimeException(e); }
    }
    public HashSet<String> obtenerTopicos(Object mensaje,RSA rsaServidor) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        if(mensaje instanceof Mensaje) {
            Mensaje mensajeRecibido=(Mensaje) mensaje;
            String mensajeRecibidoString=verificarFirmaDigital(rsaServidor,mensajeRecibido);
            if(mensajeRecibidoString!=null) {
                HashSet<String> topicosServidor=new HashSet<>();
                String topico="";
                for(int i=0;i<mensajeRecibidoString.length();i++) {
                    if(mensajeRecibidoString.charAt(i)!='.') { topico+=mensajeRecibidoString.charAt(i); }
                    else {
                        topicosServidor.add(topico);
                        topico="";
                    }
                }
                return topicosServidor;
            }
        }
        return null;
    }
}