import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Cette classe permet la reception d'un paquet UDP sur le port de reception
 * UDP/DNS. Elle analyse le paquet et extrait le hostname
 * 
 * Il s'agit d'un Thread qui ecoute en permanance pour ne pas affecter le
 * deroulement du programme
 * 
 * @author Max
 *
 */

public class UDPReceiver extends Thread {
	/**
	 * Les champs d'un Packet UDP 
	 * --------------------------
	 * En-tete (12 octects) 
	 * Question : l'adresse demande 
	 * Reponse : l'adresse IP
	 * Autorite :
	 * info sur le serveur d'autorite 
	 * Additionnel : information supplementaire
	 */

	/**
	 * Definition de l'En-tete d'un Packet UDP
	 * --------------------------------------- 
	 * Identifiant Parametres 
	 * QDcount
	 * Ancount
	 * NScount 
	 * ARcount
	 * 
	 * L'identifiant est un entier permettant d'identifier la requete. 
	 * parametres contient les champs suivant : 
	 * 		QR (1 bit) : indique si le message est une question (0) ou une reponse (1). 
	 * 		OPCODE (4 bits) : type de la requete (0000 pour une requete simple). 
	 * 		AA (1 bit) : le serveur qui a fourni la reponse a-t-il autorite sur le domaine? 
	 * 		TC (1 bit) : indique si le message est tronque.
	 *		RD (1 bit) : demande d'une requete recursive. 
	 * 		RA (1 bit) : indique que le serveur peut faire une demande recursive. 
	 *		UNUSED, AD, CD (1 bit chacun) : non utilises. 
	 * 		RCODE (4 bits) : code de retour.
	 *                       0 : OK, 1 : erreur sur le format de la requete,
	 *                       2: probleme du serveur, 3 : nom de domaine non trouve (valide seulement si AA), 
	 *                       4 : requete non supportee, 5 : le serveur refuse de repondre (raisons de s�ecurite ou autres).
	 * QDCount : nombre de questions. 
	 * ANCount, NSCount, ARCount : nombre d�entrees dans les champs �Reponse�, Autorite,  Additionnel.
	 */

	protected final static int BUF_SIZE = 1024;
	protected String SERVER_DNS = null;//serveur de redirection (ip)
	protected int portRedirect = 53; // port  de redirection (par defaut)
	protected int port; // port de r�ception
	private String adrIP = null; //bind ip d'ecoute
	private String DomainName = "";
	private String DNSFile = null;
	private boolean RedirectionSeulement = false;
	private boolean badRequest = false;
	private int c; //used to read bits
	private int bytesToRead; //used to loops through byte sequences
	private int ancount; //answer count
	private int qr; // Query(0) or response(1)
	
	
	private class ClientInfo { //quick container
		public String client_ip = null;
		public int client_port = 0;
	};
	private HashMap<Integer, ClientInfo> Clients = new HashMap<>();
	
	private boolean stop = false;

	
	public UDPReceiver() {
	}

	public UDPReceiver(String SERVER_DNS, int Port) {
		this.SERVER_DNS = SERVER_DNS;
		this.port = Port;
	}
	
	
	public void setport(int p) {
		this.port = p;
	}

	public void setRedirectionSeulement(boolean b) {
		this.RedirectionSeulement = b;
	}

	public String gethostNameFromPacket() {
		return DomainName;
	}

	public String getAdrIP() {
		return adrIP;
	}

	private void setAdrIP(String ip) {
		adrIP = ip;
	}

	public String getSERVER_DNS() {
		return SERVER_DNS;
	}

	public void setSERVER_DNS(String server_dns) {
		this.SERVER_DNS = server_dns;
	}



	public void setDNSFile(String filename) {
		DNSFile = filename;
	}

	public void run() {
		try {
			DatagramSocket serveur = new DatagramSocket(this.port); // *Creation d'un socket UDP
		
			
			// *Boucle infinie de recpetion
			while (!this.stop) {
				byte[] buff = new byte[0xFF];
				DatagramPacket paquetRecu = new DatagramPacket(buff,buff.length);
				System.out.println("Serveur DNS  "+serveur.getLocalAddress()+"  en attente sur le port: "+ serveur.getLocalPort());

				// *Reception d'un paquet UDP via le socket
				serveur.receive(paquetRecu);
				
				System.out.println("paquet recu du  "+paquetRecu.getAddress()+"  du port: "+ paquetRecu.getPort());
				

				// *Creation d'un DataInputStream ou ByteArrayInputStream pour
				// manipuler les bytes du paquet

				ByteArrayInputStream TabInputStream = new ByteArrayInputStream (paquetRecu.getData());
				
				TabInputStream.skip(2);
				c= TabInputStream.read();				
				qr = Character.getNumericValue(String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0').charAt(0)); // parsing QR code from byte
				
				System.out.println("qr=" + qr);
				
				// ****** Dans le cas d'un paquet requete *****
				if(qr==0){
					
					// *Lecture du Query Domain name, a partir du 13 byte					
					TabInputStream.skip(9);
					//System.out.println(255-TabInputStream.available());
					
					while((bytesToRead = TabInputStream.read())!=0){
						//System.out.println("Bytes to read: " + bytesToRead);
						
						for(int i=0; i<bytesToRead; i++){
							c = TabInputStream.read();
							//System.out.println(c);
							DomainName += Character.toUpperCase((char)c);
						}
						DomainName +=".";
					}
					DomainName = DomainName.substring(0, DomainName.length()-1);
					System.out.println(DomainName);	
					
					//skip if not Type A and Class 1
					boolean badRequest = false;
					
					for (int i=0; i<2; i++){
						TabInputStream.skip(1);
						if((c=TabInputStream.read())!=1){							
							badRequest=true;
						}
					}
					
					if(!badRequest){
						// *Sauvegarde de l'adresse, du port et de l'identifiant de la requete
						adrIP = paquetRecu.getAddress().toString();
						port = paquetRecu.getPort();
						
						
						// *Si le mode est redirection seulement
						if (RedirectionSeulement){
							// *Rediriger le paquet vers le serveur DNS
							UDPSender sender = new UDPSender(SERVER_DNS, 53, serveur);  //CHANGE THIS AT SCHOOL
							sender.SendPacketNow(paquetRecu);
						}
						
						// *Sinon
						else{
							
							QueryFinder qf = new QueryFinder("DNSFILE.TXT");
						
							// *Rechercher l'adresse IP associe au Query Domain name
							// dans le fichier de correspondance de ce serveur					
							List<String> addresses = qf.StartResearch(DomainName);						
							
							
							// *Si la correspondance n'est pas trouvee
							if(addresses.size()==0){
								// *Rediriger le paquet vers le serveur DNS		
								UDPSender sender = new UDPSender(SERVER_DNS, 53, serveur);  //CHANGE THIS AT SCHOOL
								sender.SendPacketNow(paquetRecu);
								
							}
							// *Sinon	
							else { 							
								// *Creer le paquet de reponse a l'aide du UDPAnswerPaquetCreator
								UDPAnswerPacketCreator apc = UDPAnswerPacketCreator.getInstance();
								buff = apc.CreateAnswerPacket(buff, addresses);
								// *Placer ce paquet dans le socket
								DatagramPacket paquetEnvoye = new DatagramPacket(buff,buff.length);
								UDPSender sender = new UDPSender("127.0.0.1", port, serveur);  
								
								// *Envoyer le paquet
								sender.SendPacketNow(paquetEnvoye);							
							}
						}
					}
					DomainName = "";					
					
				}
				// ****** Dans le cas d'un paquet reponse *****
				else{
					
					// *Get to ANCOUNT
					TabInputStream.skip(4);
					ancount = TabInputStream.read();
					System.out.println(ancount);
										
					// *Lecture du Query Domain name, a partir du 13 byte
					TabInputStream.skip(4);					
					
					while((bytesToRead = TabInputStream.read())!=0){
						for(int i=0; i<bytesToRead; i++){
							c = TabInputStream.read();							
							DomainName += Character.toUpperCase((char)c);
						}
						DomainName +=".";
					}
					DomainName = DomainName.substring(0, DomainName.length()-1);
					System.out.println(DomainName);					
										
					//Variables for file manipulations
					String addresse = "";
					AnswerRecorder aw = new AnswerRecorder("DNSFILE.TXT");
					QueryFinder qf = new QueryFinder("DNSFILE.TXT");
					List<String> addresses = qf.StartResearch(DomainName);	
					boolean addToFile = false;
					if( addresses.size()==0){
						addToFile = true;
					}
					
					
					// *Passe par dessus les premiers champs du ressource record
					// pour arriver au ressource data qui contient l'adresse IP associe
					//  au hostname (dans le fond saut de 16 bytes)
					TabInputStream.skip(16);
					
					// *Capture de ou des adresse(s) IP (ANCOUNT est le nombre
					// de r�ponses retourn�es)		
					for(int i=0; i<ancount; i++){
						for(int j=0; j<4; j++){
							c = TabInputStream.read();
							addresse +=c;
							if(j<3){
								addresse +=".";
							}
						}
						
						// *Ajouter la ou les correspondance(s) dans le fichier DNS
						// si elles ne y sont pas deja						
						if(addToFile){
							aw.StartRecord(DomainName, addresse);
							addresses.add(addresse);
						}
						System.out.println(addresse);
						System.out.println(TabInputStream.available());
						addresse = "";
						
						// Ignore addresses after 14 entries because InputStream can't handle that much data (looking at you Google.com)
						if(TabInputStream.available()>12){
							TabInputStream.skip(12);
						}
						else{
							break;
						}
					}
					
					// *Faire parvenir le paquet reponse au demandeur original,
					// ayant emis une requete avec cet identifiant
					
					UDPAnswerPacketCreator apc = UDPAnswerPacketCreator.getInstance();
					buff = apc.CreateAnswerPacket(buff, addresses);
					// *Placer ce paquet dans le socket
					DatagramPacket paquetEnvoye = new DatagramPacket(buff,buff.length);
					// *Envoyer le paquet
					UDPSender sender = new UDPSender("127.0.0.1", port, serveur);  
					sender.SendPacketNow(paquetEnvoye);
					//serveur.send(paquetEnvoye);
					
					DomainName="";
				}
			}
//			serveur.close(); //closing server
		} catch (Exception e) {
			System.err.println("Probl�me � l'ex�cution :");
			e.printStackTrace(System.err);
		}
	}
}
