import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
public class MainServidor {
    public static void main(String[] args) {
        Scanner entrada=new Scanner(System.in);
        System.out.print("Ingrese un puerto: ");
        int puerto=entrada.nextInt();
        try(ServerSocket puertoServidor=new ServerSocket(puerto)) {

            // crea su clave publica y privada
            RSA rsaServidor=new RSA();
            rsaServidor.genKeyPair(4096);

            // se establece el servidor
            Servidor servidor=new Servidor(new HashMap<>(),new HashMap<>(),new HashMap<>(),new HashSet<>(),rsaServidor,puertoServidor);
            System.out.println("Servidor escuchando en el puerto "+puerto+".");

            // se crea el hashset con los topicos y se crea el chat general automaticamente
            servidor.getClientesPorTopico().put("General",new HashSet<>());

            do {

                // escucha constantemente en busca de clientes queriendo conectarse
                Socket conexion=servidor.getPuerto().accept();

                // cuando detecta una conexión, la administra en un hilo secundario
                Thread hiloCliente=new Thread(() -> {

                    try {
                        PrintWriter impresor=new PrintWriter(conexion.getOutputStream(),true);
                        BufferedReader lector=new BufferedReader(new InputStreamReader(conexion.getInputStream()));
                        ObjectInputStream inputStream = new ObjectInputStream(conexion.getInputStream());
                        ObjectOutputStream outputStream = new ObjectOutputStream(conexion.getOutputStream());
                        servidor.getOutputStreamsClientes().put(conexion,outputStream);
                        RSA rsaCliente=new RSA();

                        // añade al nuevo cliente automaticamente al chat general y a la lista de clientes conectados
                        servidor.getClientesPorTopico().get("General").add(conexion);
                        servidor.getClientesConectados().add(conexion);

                        // le manda su clave publica
                        impresor.println(servidor.getClaves().getPublicKeyString());

                        // recibe la clave publica del cliente y la agrega al hashmap
                        rsaCliente.setPublicKeyString(lector.readLine());
                        servidor.getClavesPublicasClientes().put(conexion,rsaCliente);

                        // le manda los topicos por primera vez
                        servidor.mandarTopicos(conexion);
                        boolean terminar=false;

                        do {

                            // espera a un comando del cliente
                            Object mensaje=inputStream.readObject();

                            if(mensaje instanceof Mensaje) {

                                // lo desencripta y verifica la firma digital
                                Mensaje mensajeRecibido=(Mensaje) mensaje;
                                String mensajeRecibidoString=servidor.verificarFirmaDigital(rsaCliente,mensajeRecibido);

                                // si la firma coincide lo evalua
                                if(mensajeRecibidoString!=null) {
                                    if(mensajeRecibidoString.charAt(0)=='@' || (mensajeRecibidoString.charAt(0)=='-' && mensajeRecibidoString.charAt(1)=='g')) { servidor.enviarMensaje(conexion,mensajeRecibidoString); }
                                    else if(mensajeRecibidoString.charAt(1)=='s' || mensajeRecibidoString.charAt(1)=='d') { servidor.aniadirQuitarSuscripcion(conexion,mensajeRecibidoString); }
                                    else if(mensajeRecibidoString.charAt(1)=='b') { servidor.buscarTopico(outputStream,conexion,mensajeRecibidoString); }
                                    else if(mensajeRecibidoString.charAt(1)=='n') {
                                        HashSet<Socket> clientesSuscritos=new HashSet<>();
                                        clientesSuscritos.add(conexion);
                                        servidor.getClientesPorTopico().put(mensajeRecibidoString.substring(4,mensajeRecibidoString.length()),clientesSuscritos);
                                        for(Socket cliente:servidor.getClientesConectados()) {
                                            if(conexion!=cliente) { servidor.mandarTopicos(cliente); }
                                        }
                                    }
                                    else {
                                        Mensaje mensajeFinal=servidor.obtenerObjetoMensaje(servidor.getClavesPublicasClientes().get(conexion),mensajeRecibidoString);
                                        servidor.getOutputStreamsClientes().get(conexion).writeObject(mensajeFinal);
                                        // impresor.println(mensajeRecibidoString);
                                        terminar=!terminar;
                                    }
                                }

                            }

                        } while(!terminar);
                        servidor.eliminarCliente(conexion);
                        impresor.close();
                        lector.close();
                        conexion.close();
                    } catch(IOException | NoSuchAlgorithmException | ClassNotFoundException | InvalidKeySpecException | NoSuchPaddingException | BadPaddingException | InvalidKeyException | NoSuchProviderException | IllegalBlockSizeException e) { throw new RuntimeException(e); }
                });

                // inicia el hilo para el cliente
                hiloCliente.start();

            } while(true);

            // para que el servidor este esperando una nueva conexion:
            // Socket conexion=puertoServidor.accept();

            // para mandar informacion:
            // PrintWriter impresor=new PrintWriter(conexion.getOutputStream(),true);
            // System.out.print("Ingrese su mensaje: ");
            // entrada.nextLine();
            // impresor.println(entrada.nextLine());
            // el impresor debe cerrarse cuando se envio la informacion:
            // impresor.close();

            // para recibir informacion:
            // BufferedReader lector=new BufferedReader(new InputStreamReader(conexion.getInputStream()));
            // String mensaje=lector.readLine();
            // el lector debe cerrarse cuando se recibio la informacion:
            // lector.close();

            // la conexion debe cerrarse al final de la ejecucion:
            // conexion.close();

        } catch(IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) { throw new RuntimeException(e); }
    }
}