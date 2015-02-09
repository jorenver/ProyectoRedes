import java.net.*;
import java.io.*;
import java.util.logging.*;
import java.util.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.lang.*;


public class Servidor extends JFrame implements Observer{
	private ServerSocket servidor;
	private static int pruerto = 9500;
	private  ArrayList<ManejadorCliente> clientes;
	private int i=0;
	private Container c;
	private Button btnIniciar;
	private Button btnCerrar;
	public Servidor(){
		try{
			
	    	setSize(300,300);
			setDefaultCloseOperation(EXIT_ON_CLOSE);
			c= getContentPane();
			c.setLayout(new FlowLayout());
			btnIniciar=new Button("Iniciar Servidor");
			btnCerrar=new Button("Cerrar Servidor");
			btnIniciar.addActionListener(ListenerBotonIniciar);
			btnCerrar.addActionListener(ListenerBotonCerrar);
			c.add(btnIniciar);
			c.add(btnCerrar);
			servidor =new ServerSocket(pruerto);
			clientes = new ArrayList<ManejadorCliente>();
			setVisible(true);			
		}catch(Exception e){};
	}

	

    ActionListener ListenerBotonIniciar =new ActionListener(){
		public void actionPerformed(ActionEvent e){
			hilo.start();
			System.out.println ("Servidor Iniciado");

		}
	
	};

	ActionListener ListenerBotonCerrar =new ActionListener(){
		public void actionPerformed(ActionEvent e){
			hilo.stop();
			System.out.println ("Servidor Cerrado");
		}
	
	};


	Thread hilo =new Thread(){
		//acepta la coneccion de todos los clientes
		@Override
	    public void run() {
	        while(true){
	            try {
	            	Socket socket;
	                socket = servidor.accept();
	                System.out.println ("se Conecto: "+i);
	                i++;
	                ManejadorCliente m =new ManejadorCliente(socket,"Cliente"+i);
	                m.setObserver(Servidor.this);
	                clientes.add(m);
	                m.start();
	            } catch (IOException e) {};
	        }
	    }
	
	};

	@Override   
	public void update(String s) {
		for(ManejadorCliente c : clientes){
			c.enviarMensaje(s+"\n");
		}
	}
	

	public static void main(String args[]){
		new Servidor();
	}

}