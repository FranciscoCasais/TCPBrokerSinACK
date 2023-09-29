import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import javax.crypto.*;
public class Servidor implements FirmaDigital {
    private HashSet<Cliente> clientes;
    private HashSet<String> topicos;
    private RSA claves;
    private ServerSocket puerto;
    public Servidor() {
        clientes=new HashSet<>();
        topicos=new HashSet<>();
        claves=null;
        puerto=null;
    }
    public Servidor(HashSet<Cliente> clientes, HashSet<String> topicos, RSA claves, ServerSocket puerto) {
        this.clientes = clientes;
        this.topicos = topicos;
        this.claves = claves;
        this.puerto = puerto;
    }
    public HashSet<Cliente> getClientes() { return clientes; }
    public void setClientes(HashSet<Cliente> clientes) { this.clientes=clientes; }
    public HashSet<String> getTopicos() { return topicos; }
    public void setTopicos(HashSet<String> topicos) { this.topicos=topicos; }
    public RSA getClaves() { return claves; }
    public void setClaves(RSA claves) { this.claves=claves; }
    public ServerSocket getPuerto() { return puerto; }
    public void setPuerto(ServerSocket puerto) { this.puerto=puerto; }
    public void agregarTopico(Cliente emisor,String comando) throws NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {
        String topico=FirmaDigital.obtenerTopico2(comando);
        topicos.add(topico);
        for(Cliente cliente:clientes) {
            if(!cliente.equals(emisor)) mandarTopicos(cliente);
        }
    }
    public void enviarMensaje(Cliente emisor,String comando) throws NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {
        String mensajeString,topico="";
        if(comando.charAt(1)=='g') {
            topico="General";
            mensajeString="/"+emisor.getNombre()+" dice en @"+topico+": "+comando.substring(3);
        } else {
            topico=FirmaDigital.obtenerTopico1(comando);
            mensajeString="/"+emisor.getNombre()+" dice en @"+topico+": "+comando.substring(topico.length()+2);
        }
        for(Cliente cliente:clientes) {
            if(cliente.getTopicosSuscrito().contains(topico)) {
                Mensaje mensaje=FirmaDigital.obtenerObjetoMensaje(cliente.getClavePublica(),claves,mensajeString);
                cliente.getOutputStream().writeObject(mensaje);
            }
        }
    }
    public void mandarTopicos(Cliente cliente) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {
        String cadenaTopicos="";
        for(String topico:topicos) { cadenaTopicos+=topico+'.'; }
        Mensaje mensaje=FirmaDigital.obtenerObjetoMensaje(cliente.getClavePublica(),claves,cadenaTopicos);
        cliente.getOutputStream().writeObject(mensaje);
    }
    public void suscribirDesuscribirCliente(Cliente cliente,String mensaje) {
        String topico=FirmaDigital.obtenerTopico2(mensaje);
        for(Cliente c:clientes) {
            if(c.equals(cliente) && mensaje.charAt(1)=='s') c.getTopicosSuscrito().add(topico);
            else if(c.equals(cliente) && mensaje.charAt(1)=='d') c.getTopicosSuscrito().remove(topico);
        }
    }
    /* public static String generarClaveAleatoria() {
        String caracteres="qwertyuiopasdfghjklzxcvbnm1234567890",claveAleatoria="";

        return claveAleatoria;
    } */
    public static void main(String[] args) {
        Scanner entrada=new Scanner(System.in);
        System.out.print("Ingrese un puerto: ");
        try(ServerSocket puerto=new ServerSocket(entrada.nextInt())) {

            // crea su clave publica y privada
            RSA claves=new RSA();
            claves.genKeyPair(4096);

            // se establece el servidor
            Servidor servidor=new Servidor(new HashSet<>(),new HashSet<>(),claves,puerto);
            servidor.getTopicos().add("General");
            System.out.println("Servidor escuchando en el puerto "+servidor.getPuerto().getLocalPort()+".");

            // incia un hilo donde pide una entrada para ver varios comandos
            /* Thread hiloComandosServidor=new Thread(() -> {

            });
            hiloComandosServidor.start(); */
            // TODO: hilo comandos servidor

            do {

                // escucha constantemente en busca de clientes queriendo conectarse
                Socket conexion=servidor.getPuerto().accept();

                // cuando detecta una conexión, la administra en un hilo secundario
                Thread hiloCliente=new Thread(() -> {
                    try {

                        // crea los lectores e impresores necesarios
                        PrintWriter impresor=new PrintWriter(conexion.getOutputStream(),true);
                        BufferedReader lector=new BufferedReader(new InputStreamReader(conexion.getInputStream()));
                        ObjectInputStream inputStream = new ObjectInputStream(conexion.getInputStream());
                        ObjectOutputStream outputStream = new ObjectOutputStream(conexion.getOutputStream());

                        // le manda la clave publica al cliente
                        impresor.println(servidor.getClaves().getPublicKeyString());

                        // recibe la clave publica del cliente
                        RSA clavePublicaCliente=new RSA();
                        clavePublicaCliente.setPublicKeyString(lector.readLine());

                        // crea la clave simetrica AES y se la manda al cliente
                        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                        keyGenerator.init(256);
                        SecretKey claveSimetrica = keyGenerator.generateKey();
                        byte[] keyBytes = claveSimetrica.getEncoded();
                        String keyString = Base64.getEncoder().encodeToString(keyBytes);

                        System.out.println(keyString);

                        Mensaje mensajeClaveSimetrica=FirmaDigital.obtenerObjetoMensaje(clavePublicaCliente,claves,keyString);
                        outputStream.writeObject(mensajeClaveSimetrica);
                        // TODO: creacion y envio de la clave simetrica

                        // recibe el nombre del cliente
                        Object objetoRecibidoNombre=inputStream.readObject();
                        String nombreCliente=FirmaDigital.verificarFirmaDigital(objetoRecibidoNombre,clavePublicaCliente,claves);

                        // instancia el cliente y lo agrega al hashset
                        HashSet<String> topicosSuscrito=new HashSet<>();
                        topicosSuscrito.add("General");
                        Cliente cliente=new Cliente(topicosSuscrito,outputStream,clavePublicaCliente,claveSimetrica,conexion,nombreCliente);
                        servidor.getClientes().add(cliente);
                        System.out.println("Nuevo cliente conectado: "+cliente.getNombre()+" ("+cliente.getConexion().getInetAddress().toString().substring(1)+")");

                        // le manda los topicos por primera vez
                        servidor.mandarTopicos(cliente);

                        do {

                            // el servidor escucha permanentemente en busca de un comando entrante del cliente
                            Object objetoRecibido=inputStream.readObject();
                            String mensajeRecibido=FirmaDigital.verificarFirmaDigital(objetoRecibido,clavePublicaCliente,claves);

                            // lo evalua
                            if(mensajeRecibido.charAt(1)=='g' || mensajeRecibido.charAt(0)=='@') servidor.enviarMensaje(cliente,mensajeRecibido);
                            else if(mensajeRecibido.charAt(1)=='s' || mensajeRecibido.charAt(1)=='d') servidor.suscribirDesuscribirCliente(cliente,mensajeRecibido);
                            else if(mensajeRecibido.charAt(1)=='c') servidor.agregarTopico(cliente,mensajeRecibido);

                            // break;

                        } while(true);

                        // servidor.getClientes().remove(cliente);
                        // impresor.close();
                        // lector.close();
                        // inputStream.close();
                        // outputStream.close();
                        // System.out.println("Se desconectó un cliente: "+cliente.getNombre()+" ("+cliente.getConexion().getInetAddress().toString().substring(1)+")");

                    } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | ClassNotFoundException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchProviderException | MensajeModificadoException | ObjetoTipoIncorrectoException e) { e.getMessage(); }
                });

                // inicia el hilo
                hiloCliente.start();

            } while(true);
            // TODO: apagar manualmente el servidor

        } catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException e) { e.getMessage(); }
    }
}