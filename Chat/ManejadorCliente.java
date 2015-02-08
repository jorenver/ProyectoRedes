import java.io.*;
import java.net.*;
import java.util.logging.*;
import java.util.*;
import javax.swing.*;

public class ManejadorCliente extends Thread {

    private Socket socket;
    private DataOutputStream salida;
    private DataInputStream entrada;
    private String nom;
    private int puerto=9500;
    private Observer observer;

    public ManejadorCliente(Socket socket, String nom) {
        this.socket = socket;
        this.nom = nom;
        try {
            salida = new DataOutputStream(socket.getOutputStream());
            entrada = new DataInputStream(socket.getInputStream());
            System.out.println ("Manejador Creado");
        } catch (IOException e) {};
        

    }

    public void desconnectar() {
        try {
            socket.close();
        } catch (IOException e) {};
    }

    public String leerMensaje(){
        String s;
        try{
            //System.out.println ("Aqui es");
            s=entrada.readLine();
            return s;
        }catch(Exception e){};
        return null;    
    }

    public void enviarMensaje(String s){
        try{
            System.out.println ("se envio mensaje al cliente");
            salida.writeUTF(s);
        }catch(Exception e){};
    }

    //escucha los mensajes de los clientes
    @Override
    public void run() {
        while(true){
                String s;
                s=leerMensaje();
                if(s!=null){
                    System.out.println (s);
                    observer.update(s);
                }
        }
    }

    public void setObserver(Observer observer){
        this.observer=observer;
    }

    
}