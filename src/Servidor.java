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
public class Servidor extends Thread {
    private HashMap<Socket,ObjectOutputStream> outputStreamsClientes;
    private HashMap<Socket,RSA> clavesPublicasClientes;
    private HashMap<String,HashSet<Socket>> clientesPorTopico;
    private HashSet<Socket> clientesConectados;
    private RSA claves;
    private ServerSocket puerto;
    public Servidor(HashMap<Socket,ObjectOutputStream> outputStreamsClientes,HashMap<Socket,RSA> clavesPublicasClientes,HashMap<String,HashSet<Socket>> clientesPorTopico,HashSet<Socket> clientes,RSA claves,ServerSocket puertoServidor) {
        this.outputStreamsClientes=outputStreamsClientes;
        this.clavesPublicasClientes=clavesPublicasClientes;
        this.clientesPorTopico=clientesPorTopico;
        this.clientesConectados =clientes;
        this.claves=claves;
        this.puerto=puertoServidor;
    }
    public HashMap<Socket,ObjectOutputStream> getOutputStreamsClientes() { return outputStreamsClientes; }
    public HashMap<Socket,RSA> getClavesPublicasClientes() { return clavesPublicasClientes; }
    public HashMap<String,HashSet<Socket>> getClientesPorTopico() { return clientesPorTopico; }
    public HashSet<Socket> getClientesConectados() { return clientesConectados; }
    public RSA getClaves() { return claves; }
    public ServerSocket getPuerto() { return puerto; }
    public void setOutputStreamsClientes(HashMap<Socket,ObjectOutputStream> outputStreamsClientes) { this.outputStreamsClientes=outputStreamsClientes; }
    public void setClavesPublicasClientes(HashMap<Socket,RSA> clavesPublicasClientes) { this.clavesPublicasClientes=clavesPublicasClientes; }
    public void setClientesPorTopico(HashMap<String,HashSet<Socket>> clientesPorTopico) { this.clientesPorTopico = clientesPorTopico; }
    public void setClientesConectados(HashSet<Socket> clientesConectados) { this.clientesConectados = clientesConectados; }
    public void setClaves(RSA claves) { this.claves=claves; }
    public void setPuerto(ServerSocket puerto) { this.puerto=puerto; }
    public String verificarFirmaDigital(RSA rsaCliente,Mensaje mensajeRecibido) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // desencripta el mensaje 1 hasheado con la clave pública del cliente
        String mensaje1Desencriptado=rsaCliente.desencriptarClavePublica(mensajeRecibido.getMensaje1());

        // desencripta el mensaje 2 con la clave privada del servidor
        String mensaje2Desencriptado=getClaves().desencriptarClavePrivada(mensajeRecibido.getMensaje2());

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

        // lo encripta con la clave privada del servidor
        String mensaje1=getClaves().encriptarClavePrivada(hashHex.toString());
        return mensaje1;

    }
    public String obtenerMensaje2(RSA rsaCliente,String mensaje) throws NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {

        // lo encripta con la clave publica del servidor
        String mensaje2=rsaCliente.encriptarClavePublica(mensaje);
        return mensaje2;

    }
    public Mensaje obtenerObjetoMensaje(RSA rsaCliente,String comando) throws NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {
        String mensaje1=this.obtenerMensaje1(comando);
        String mensaje2=this.obtenerMensaje2(rsaCliente,comando);
        Mensaje mensajeFinal=new Mensaje(mensaje1,mensaje2);
        return mensajeFinal;
    }
    public void aniadirQuitarSuscripcion(Socket conexion,String comando) {
        boolean entrar=false;
        String topico="";
        for(int i=0;i<comando.length();i++) {
            if(entrar) { topico+=comando.charAt(i); }
            else if(comando.charAt(i)==' ') { entrar=!entrar; }
        }
        if(comando.charAt(1)=='s') { this.getClientesPorTopico().get(topico).add(conexion); }
        else { this.getClientesPorTopico().get(topico).remove(conexion); }
    }
    public void buscarTopico(ObjectOutputStream outputStream,Socket conexion,String comando) throws IOException {
        boolean entrar=false;
        // ObjectOutputStream outputStream = new ObjectOutputStream(conexion.getOutputStream());
        String topico="";
        for(int i=0;i<comando.length();i++) {
            if(entrar) { topico+=comando.charAt(i); }
            else if(comando.charAt(i)==' ') { entrar=!entrar; }
        }
        try {
            if(clientesPorTopico.containsKey(topico)) { this.mandarTopicos(conexion); }
            else {
                String mensaje="0";
                Mensaje mensajeFinal=obtenerObjetoMensaje(clavesPublicasClientes.get(conexion),mensaje);
                outputStream.writeObject(mensajeFinal);
                // PrintWriter impresor=new PrintWriter(conexion.getOutputStream(),true);
            }
        } catch(IOException | NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | InvalidKeySpecException | InvalidKeyException | NoSuchProviderException | IllegalBlockSizeException e) { throw new RuntimeException(e); }
    }
    public void eliminarCliente(Socket conexion) {
        clientesConectados.remove(conexion);
        for(HashSet<Socket> clientesSuscritos:clientesPorTopico.values()) {
            for(Socket c:clientesSuscritos) {
                if(c.equals(conexion)) { clientesSuscritos.remove(c); }
            }
        }
    }
    public void enviarMensaje(Socket conexion,String comando) throws IOException {
        int i;
        // ObjectOutputStream outputStream = new ObjectOutputStream(conexion.getOutputStream());
        String topico="";
        if(comando.charAt(0)=='-') {
            i=2;
            topico="General";
        } else {
            i=1;
            while(comando.charAt(i)!=' ') {
                topico+=comando.charAt(i);
                i++;
            }
        }
        String mensajeString=conexion.getInetAddress()+" dice en @"+topico+": "+comando.substring(i+1,comando.length());
        for(Socket cliente: this.getClientesPorTopico().get(topico)) {
            try {
                // PrintWriter impresor=new PrintWriter(cliente.getOutputStream(),true);
                Mensaje mensajeFinal=obtenerObjetoMensaje(clavesPublicasClientes.get(cliente),mensajeString);
                // ObjectOutputStream outputStream=new ObjectOutputStream(cliente.getOutputStream());
                outputStreamsClientes.get(cliente).writeObject(mensajeFinal);
                // impresor.println(conexion.getInetAddress()+" dice en @"+topico+": "+comando.substring(i+1,comando.length()));
            } catch(IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeySpecException | InvalidKeyException | NoSuchProviderException e) { throw new RuntimeException(e); }
        }
    }
    public void mandarTopicos(Socket conexion) {
        try {
            // ObjectOutputStream outputStream = new ObjectOutputStream(conexion.getOutputStream());
            String cadenaTopicos="";
            for(String topico:clientesPorTopico.keySet()) { cadenaTopicos+=topico+'.'; }
            Mensaje mensajeFinal=obtenerObjetoMensaje(clavesPublicasClientes.get(conexion),cadenaTopicos);
            outputStreamsClientes.get(conexion).writeObject(mensajeFinal);
            // PrintWriter impresor=new PrintWriter(conexion.getOutputStream(),true);
            // impresor.println(cadenaTopicos);
        } catch(IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeySpecException | InvalidKeyException | NoSuchProviderException e) { throw new RuntimeException(e); }
    }
}