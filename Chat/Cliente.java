import java.net.*;
import java.io.*;

public class Cliente {
	private Socket socket;
	private int puerto=9500;
	private String ip ="127.0.0.1";
	private DataOutputStream salida;
	private DataInputStream entrada;
	private Observer observer;
	private String nombre;

	public Cliente(String nombre){
		this.nombre=nombre;
	}


	public void iniciarConeccion(){
		try{
			
			socket = new Socket(ip,puerto);
			//para enviar mensajes
			salida = new DataOutputStream(socket.getOutputStream());
            //para resivir mensaje
            entrada = new DataInputStream(socket.getInputStream());
            System.out.println ("Conectando...");
            recibirMensajes.start();
		}catch(Exception e){

		};
	}

	public void terminarConeccion(){
		try{
			socket.close();
		}catch(Exception e){};
	}

	public void enivarMensaje(String s){
		try{
			salida.writeUTF(nombre+" Dice: "+s);
			System.out.println ("envio mensaje al manejador");
		}catch(Exception e){};
	}

	public String leerMensaje(){
		try{
			return entrada.readLine();
		}catch(Exception e){};
		return null;	
	}

	public void setObserver(Observer observer){
		this.observer=observer;
	}

	Thread recibirMensajes =new Thread(){
		//acepta la coneccion de todos los clientes
		@Override
	    public void run() {
	    	String s;
	        while(true){
	            
	            	s=leerMensaje();
	            	if(s!=null){
	            		System.out.println (s);
	            		observer.update(s);
	            	}
	            
	        }
	    }
	
	};

}