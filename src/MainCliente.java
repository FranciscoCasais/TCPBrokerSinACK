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
public class MainCliente {
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
    public static void main(String[] args) {
        Scanner entrada=new Scanner(System.in);
        System.out.print("Ingrese la IP del servidor: ");
        String ipServidor=entrada.nextLine();
        System.out.print("Ingrese el puerto del servidor: ");
        int puertoServidor=entrada.nextInt();
        entrada.nextLine();
        try(Socket conexion=new Socket(ipServidor,puertoServidor)) {

            // crea su clave publica y privada
            RSA rsaCliente=new RSA();
            rsaCliente.genKeyPair(4096);

            RSA rsaServidor=new RSA();

            // se establece la conexion con el servidor
            Cliente cliente=new Cliente(new HashSet<>(),new HashSet<>(),null,rsaCliente,rsaServidor,conexion);
            System.out.println("Se conectó exitosamente al servidor.");
            BufferedReader lector=new BufferedReader(new InputStreamReader(conexion.getInputStream()));
            ObjectOutputStream outputStream = new ObjectOutputStream(conexion.getOutputStream());
            ObjectInputStream inputStream = new ObjectInputStream(conexion.getInputStream());
            PrintWriter impresor=new PrintWriter(conexion.getOutputStream(),true);
            cliente.setInputStream(inputStream);

            // recibe la clave publica del servidor
            rsaServidor.setPublicKeyString(lector.readLine());
            cliente.setClavesServidor(rsaServidor);

            // le pasa al servidor su clave publica
            impresor.println(cliente.getClavesCliente().getPublicKeyString());

            // obtiene la lista de topicos del servidor automaticamente y se instancia el hashset local (topicosServidor)
            // BufferedReader lector=new BufferedReader(new InputStreamReader(conexion.getInputStream()));
            Object mensajeTopicos=inputStream.readObject();
            cliente.setTopicosServidor(cliente.obtenerTopicos(mensajeTopicos,rsaServidor));

            // se inicia un hilo secundario del cliente en el que escucha constanstemente en busca de mensajes entrantes para mostrarlos en pantalla
            Thread hiloRecepcion=new Thread(() -> {
                try {
                    boolean terminar=false;
                    do {
                        // BufferedReader lector=new BufferedReader(new InputStreamReader(conexion.getInputStream()));
                        // String mensaje=lector.readLine();
                        // ObjectInputStream inputStream=new ObjectInputStream(conexion.getInputStream());
                        // MyObjectInputStream myInputStream=new MyObjectInputStream(conexion.getInputStream());
                        // Object mensaje=myInputStream.readObject();
                        Object mensaje=inputStream.readObject();
                        if(mensaje instanceof Mensaje) {
                            Mensaje mensajeRecibido=(Mensaje) mensaje;
                            String mensajeRecibidoString=cliente.verificarFirmaDigital(cliente.getClavesServidor(),mensajeRecibido);
                            if(mensajeRecibidoString.charAt(0)=='/') { System.out.println(mensajeRecibidoString); }
                            else if(mensajeRecibidoString.equals("-fin")) {
                                // lector.close();
                                terminar=!terminar;
                            } else if(mensajeRecibidoString.equals("0")) { System.out.println("No se encontró el tópico."); }
                            else { cliente.setTopicosServidor(cliente.obtenerTopicos(mensaje,rsaServidor)); }
                        }
                    } while(!terminar);
                    cliente.getConexion().close();
                } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | ClassNotFoundException e) { throw new RuntimeException(e); }
            });
            hiloRecepcion.start();

            boolean terminar=false;
            do {

                // el cliente tiene la opcion de enviar un mensaje en cualquier momento
                String comando=entrada.nextLine();

                // verifica la sintaxis del comando
                if(verificarSintaxis(comando)) {
                    if(comando.charAt(0)=='@' || comando.charAt(1)=='s' || comando.charAt(1)=='d') {

                        // si es un mensaje a un topico en especifico / se quiere suscribir o desuscribir primero mira los topicos cargados en el hashset local (topicosServidor)
                        // si no lo encuentra ahi le pide al servidor que le vuelva a enviar los topicos en caso de que el hashset local este desactualizado, si ahi tampoco lo encuentra tira el error, si lo encuentra lo manda al servidor
                        if(cliente.buscarTopico(inputStream,outputStream,rsaServidor,comando)) {
                            if(comando.charAt(1)=='s' || comando.charAt(1)=='d') { cliente.suscribirDesuscribir(outputStream,rsaServidor,comando); }
                            else if (cliente.suscritoTopico(comando)) {
                                Mensaje mensaje=cliente.obtenerObjetoMensaje(rsaServidor,comando);
                                outputStream.writeObject(mensaje);
                            } else {
                                System.out.println("Usted no está suscrito al tópico.");
                            }
                        }

                    } else if(comando.charAt(1)=='g') {

                        // si es un mensaje al general tambien se lo manda al servidor
                        Mensaje mensaje=cliente.obtenerObjetoMensaje(rsaServidor,comando);
                        outputStream.writeObject(mensaje);
                    } else if(comando.charAt(1)=='c') {

                        // si es para crear un topico lo crea y suscribe al cliente automaticamente, despues le avisa al servidor para que actualice su lista de topicos
                        String nuevoTopico=comando.substring(4,comando.length());
                        cliente.getTopicosServidor().add(nuevoTopico);
                        cliente.getTopicosSuscrito().add(nuevoTopico);
                        String creacionTopico="-nt "+nuevoTopico;
                        Mensaje mensaje=cliente.obtenerObjetoMensaje(rsaServidor,creacionTopico);
                        outputStream.writeObject(mensaje);
                        System.out.println("Se creó el tópico \""+nuevoTopico+"\" y se le suscribió automáticamente a él.");

                    } else {

                        // si es el comando -fin le avisa al servidor que se desconecta y termina la conexion (setea la variable terminar a true)
                        Mensaje mensaje=cliente.obtenerObjetoMensaje(rsaServidor,comando);
                        outputStream.writeObject(mensaje);
                        hiloRecepcion.join();
                        terminar=!terminar;

                    }
                } else { System.out.println("Error de sintaxis. Comandos:\n\n-g mensaje para enviar mensaje al general\n@nombretópico mensaje para enviar mensaje a un tópico\n-s nombretópico para suscribirse a un tópico\n-ds nombretópico para desuscribirse de un tópico\n-ct nombretópico para crear un tópico\n-fin para desconectar"); }
            } while(!terminar);

            // cierra el lector e impresor y finaliza la conexion
            inputStream.close();
            outputStream.close();
            impresor.close();
            lector.close();

            // -------------------------------------------------------------------------------------------------

            // comandos del cliente:
            // -g mensaje: para enviar mensaje al general
            // @nombreTopico mensaje: para enviar mensaje a un topico
            // -s nombreTopico: para suscribirse a un topico
            // -ds nombreTopico: para desuscribirse de un topico
            // -ct nombreTopico: para crear un topico
            // -fin: para avisarle al servidor que se va a desconectar

            // para mandar informacion:
            // PrintWriter impresor=new PrintWriter(conexion.getOutputStream(),true);
            // impresor.println();
            // el impresor debe cerrarse cuando se envio la informacion:
            // impresor.close();

            // para recibir informacion:
            // BufferedReader lector=new BufferedReader(new InputStreamReader(conexion.getInputStream()));
            // String mensaje=lector.readLine();
            // el lector debe cerrarse cuando se recibio la informacion:
            // lector.close();

            // para terminar la conexion con el servidor:
            // conexion.close();

        } catch(IOException | InterruptedException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | InvalidKeySpecException | NoSuchProviderException | ClassNotFoundException e) { throw new RuntimeException(e); }
    }
}