import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
public class Cliente1 implements FirmaDigital {
    private HashSet<String> topicosSuscrito;
    private ObjectOutputStream outputStream;
    private RSA clavePublica;
    private SecretKey claveSimetrica;
    private Socket conexion;
    private String nombre;
    public Cliente1() {
        topicosSuscrito=new HashSet<>();
        outputStream=null;
        clavePublica=null;
        claveSimetrica=null;
        conexion=null;
        nombre="";
    }
    public Cliente1(HashSet<String> topicosSuscrito, ObjectOutputStream outputStream, RSA clavePublica, SecretKey claveSimetrica, Socket conexion, String nombre) {
        this.topicosSuscrito=topicosSuscrito;
        this.outputStream = outputStream;
        this.clavePublica = clavePublica;
        this.claveSimetrica = claveSimetrica;
        this.conexion = conexion;
        this.nombre = nombre;
    }
    public HashSet<String> getTopicosSuscrito() { return topicosSuscrito; }
    public void setTopicosSuscrito(HashSet<String> topicosSuscrito) { this.topicosSuscrito=topicosSuscrito; }
    public ObjectOutputStream getOutputStream() { return outputStream; }
    public void setOutputStream(ObjectOutputStream outputStream) { this.outputStream=outputStream; }
    public RSA getClavePublica() { return clavePublica; }
    public void setClavePublica(RSA clavePublica) { this.clavePublica=clavePublica; }
    public SecretKey getClaveSimetrica() { return claveSimetrica; }
    public void setClaveSimetrica(SecretKey claveSimetrica) { this.claveSimetrica=claveSimetrica; }
    public Socket getConexion() { return conexion; }
    public void setConexion(Socket conexion) { this.conexion=conexion; }
    public String getNombre() { return nombre; }
    public void setNombre(String nombre) { this.nombre=nombre; }
    @Override
    public String toString() { return nombre+" ("+conexion.getInetAddress().toString().substring(1)+")"; }
    public void suscribirDesuscribir(HashSet<String> topicosServidor,Mensaje mensaje,RSA clavePublicaServidor,RSA claves,String comando) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {
        String topico=FirmaDigital.obtenerTopico2(comando);
        if(!topicosServidor.contains(topico)) System.out.println("No se encontró el tópico.");
        else if(comando.charAt(1)=='s' && topicosSuscrito.contains(topico)) System.out.println("Ya está suscrito al tópico.");
        else if(comando.charAt(1)=='d' && !topicosSuscrito.contains(topico)) System.out.println("No está suscrito al tópico.");
        else if(comando.charAt(1)=='s') {
            topicosSuscrito.add(topico);
            outputStream.writeObject(mensaje);
            System.out.println("Se le suscribió al tópico.");
        } else if(comando.charAt(1)=='d') {
            topicosSuscrito.remove(topico);
            outputStream.writeObject(mensaje);
            System.out.println("Se le desuscribió del tópico.");
        }
    }
    public static boolean verificarSintaxis(String comando) {
        if(comando.equals("") || comando.charAt(0)!='-' && comando.charAt(0)!='@') { return false; }
        else {
            int i=0;
            String instruccion="";
            while(i<comando.length() && comando.charAt(i)!=' ') {
                instruccion+=comando.charAt(i);
                i++;
            }
            if(comando.charAt(0)=='@' && i<comando.length()-1) { return true; }
            else if((instruccion.equals("-g") || instruccion.equals("-s") || instruccion.equals("-ds") || instruccion.equals("-ct")) && i<comando.length()-1) { return true; }
            else if(instruccion.equals("-fin")) { return true; }
            else { return false; }
        }
    }
    public static void recibirTopicos(HashSet<String> topicosServidor,String mensajeTopicos) {
        String topico="";
        for(int i=0;i<mensajeTopicos.length();i++) {
            if(mensajeTopicos.charAt(i)!='.') { topico+=mensajeTopicos.charAt(i); }
            else {
                topicosServidor.add(topico);
                topico="";
            }
        }
    }
    public static void main(String[] args) {
        Scanner entrada=new Scanner(System.in);
        System.out.print("Ingrese la IP del servidor: ");
        String ipServidor=entrada.nextLine();
        System.out.print("Ingrese el puerto del servidor: ");
        int puertoServidor=entrada.nextInt();
        entrada.nextLine();
        try(Socket conexion=new Socket(ipServidor,puertoServidor)) {

            // crea su clave publica y privada
            RSA claves=new RSA();
            claves.genKeyPair(4096);
            RSA clavePublica=new RSA();
            clavePublica.setPublicKeyString(claves.getPublicKeyString());

            // crea los lectores e impresores necesarios
            BufferedReader lector=new BufferedReader(new InputStreamReader(conexion.getInputStream()));
            ObjectOutputStream outputStream = new ObjectOutputStream(conexion.getOutputStream());
            ObjectInputStream inputStream = new ObjectInputStream(conexion.getInputStream());
            PrintWriter impresor=new PrintWriter(conexion.getOutputStream(),true);

            // recibe la clave publica del servidor
            RSA clavePublicaServidor=new RSA();
            clavePublicaServidor.setPublicKeyString(lector.readLine());

            // le manda su clave publica
            impresor.println(claves.getPublicKeyString());

            // recibe la clave AES del servidor
            Object objetoRecibidoClaveSimetrica=inputStream.readObject();
            String keyString=FirmaDigital.verificarFirmaDigitalRSA(objetoRecibidoClaveSimetrica,clavePublicaServidor,claves);
            byte[] keyBytes = Base64.getDecoder().decode(keyString);
            SecretKey claveSimetrica = new SecretKeySpec(keyBytes, "AES");

            // se establece el nombre y se instancia el cliente
            System.out.print("Se conectó exitosamente al servidor.\nIngrese su nombre: ");
            Cliente1 cliente=new Cliente1(new HashSet<>(),outputStream,clavePublica,claveSimetrica,conexion,entrada.nextLine());
            cliente.getTopicosSuscrito().add("General");

            // le manda su nombre al servidor
            Mensaje mensajeNombre=FirmaDigital.obtenerObjetoMensajeAES(claves,cliente.getClaveSimetrica(),cliente.getNombre());
            outputStream.writeObject(mensajeNombre);

            // recibe los topicos del servidor por primera vez
            Object objetoRecibidoTopicos=inputStream.readObject();
            String mensajeTopicos=FirmaDigital.verificarFirmaDigitalAES(objetoRecibidoTopicos,clavePublicaServidor,cliente.getClaveSimetrica());
            HashSet<String> topicosServidor=new HashSet<>();
            recibirTopicos(topicosServidor,mensajeTopicos);

            // crea un hilo donde esta permanentemente escuchando en busca de mensajes entrantes
            Thread hiloRecepcion=new Thread(() -> {
                do {
                    try {
                        Object objetoRecibido=inputStream.readObject();
                        String mensajeRecibido=FirmaDigital.verificarFirmaDigitalAES(objetoRecibido,clavePublicaServidor,cliente.getClaveSimetrica());
                        if(mensajeRecibido.charAt(0)=='/') System.out.println(mensajeRecibido.substring(1));
                        else topicosServidor.add(mensajeRecibido);
                    } catch (IOException | ClassNotFoundException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | MensajeModificadoException | ObjetoTipoIncorrectoException e) { System.out.println(e.getMessage()); }
                } while(true);
            });
            hiloRecepcion.start();
            // TODO: finalizacion manual del hilo

            do {

                // el cliente tiene la opcion de ingresar un comando en cualquier momento
                String comando=entrada.nextLine();

                // lo evalua
                if(verificarSintaxis(comando)) {
                    Mensaje mensaje=FirmaDigital.obtenerObjetoMensajeAES(claves,cliente.getClaveSimetrica(),comando);
                    if(comando.charAt(1)=='g' || (comando.charAt(0)=='@' && cliente.getTopicosSuscrito().contains(FirmaDigital.obtenerTopico1(comando)))) outputStream.writeObject(mensaje);
                    else if(comando.charAt(0)=='@') System.out.println("El tópico no existe o no está suscrito a él.");
                    else if(comando.charAt(1)=='s' || comando.charAt(1)=='d') cliente.suscribirDesuscribir(topicosServidor,mensaje,clavePublicaServidor,claves,comando);
                    else if(comando.charAt(1)=='c') {
                        String topico=comando.substring(4);
                        try {
                            if(topico.contains(" ")) throw new TopicoConEspacioException("Error: El nombre del tópico no puede contener espacios.");
                            else if(!topicosServidor.contains(topico)) {
                                cliente.getTopicosSuscrito().add(topico);
                                topicosServidor.add(topico);
                                outputStream.writeObject(mensaje);
                                System.out.println("Se creó el tópico \""+topico+"\" y se le suscribió automáticamente a él.");
                            } else System.out.println("Ya existe el tópico.");
                        } catch(TopicoConEspacioException e) { System.out.println(e.getMessage()); }
                    }
                } else { System.out.println("\nError de sintaxis. Comandos:\n\n-g mensaje para enviar mensaje al general\n@nombretópico mensaje para enviar mensaje a un tópico\n-s nombretópico para suscribirse a un tópico\n-ds nombretópico para desuscribirse de un tópico\n-ct nombretópico para crear un tópico\n-fin para desconectar\n"); }

                // break;

            } while(true);

            // lector.close();
            // outputStream.close();
            // inputStream.close();
            // impresor.close();
            // TODO: desconexion manual del cliente

        } catch(IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | InvalidKeySpecException | NoSuchProviderException | ClassNotFoundException | MensajeModificadoException | ObjetoTipoIncorrectoException e) { System.out.println(e.getMessage()); }
    }
}