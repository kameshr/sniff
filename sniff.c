/**
 * File: sniff.c ver1.0
 * Date: October 25, 2004    
 * Last Modified: December 04, 2004
 *
 * Description: 
 * This program is a packet analyzer which sniffs the network device for packets and
 * extracts information from the ethernet and IP headers. It is built over the pcap library.
 *
 * The program spawns three separate processes with two shared memory buffers. The processes access
 * the shared buffer over a semaphore.
 *
 * One process dumps all the packets onto the shared memory buffer while the second process
 * reads the packets from the dump and analyzes them. The third process periodically summarises
 * the information extracted from the analysis.
 **/

#ifndef __SNIFF__
#define __SNIFF__
#define ONLINE 1
#include "headers.h"
#include "ethernet.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include "defs.h"
#include "packet_dump.h"
#include "packet_analyse.h"
#include "packet_summary.h"
#include "parse.h"


typedef void (*sighandler_t)(int);

// The "main" function
int main(int argc,char **argv)
{ 
	/***************** Declare all the variables required -- the C way! *************************************/
	int pid, pidchild;
	char *dev; 
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fcp;      /* hold compiled program     */
	bpf_u_int32 maskp;          /* subnet mask               */
	bpf_u_int32 netp;           /* ip                        */
	u_char* args = NULL;
	numPacket = INT_MAX;
	char options[250];
	/************************************** End of variables ***********************************************/

	/* Options must be passed in as a string*/
	if(argc < 2){ 
		fprintf(stdout, "************************ Sniff v2.2 ************************\n");
		fprintf(stdout,"Usage: iitm_sniff numpackets <config file>\n",argv[0]);
		fprintf(stdout,"Note: Root privileges required to run this tool.\n");
		fprintf(stdout, "Refer to User Documentation for the usage and options.\n");
		fprintf(stdout, "Report bugs and suggestions to: Kamesh R <kameshr@gmail.com>\n");
		fprintf(stdout, "************************************************************\n");
		return 0;
	}

	if(atoi(argv[1]) < -1) {
			fprintf(stderr, "[ERROR] Number of packets wrongly specified.\n");
			exit(-1);
	}
	else if(atoi(argv[1]) > 0)
		numPacket = atoi(argv[1]);

	/************************************ Initialize the network packet capture components ****************/
	fprintf(stdout, "***************** Sniff ver2.2 ****************\n");
	fprintf(stdout, "[INFO] Initializing SNIFF...\n");
	fprintf(stdout, "[INFO] Establishing connection with network devices...\n");
	/* Open a device to listen to */
	dev = pcap_lookupdev(errbuf);
	if(dev == NULL)
	{ fprintf(stderr, "[ERROR] %s\n",errbuf); exit(1); }

	/* Ask pcap for the network address and mask of the device */
	pcap_lookupnet(dev,&netp,&maskp,errbuf);

	/* Open device for reading. NOTE: defaulting to
	 * promiscuous mode*/
	descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
	if(descr == NULL)
	{ fprintf(stderr, "[ERROR] pcap_open_live(): %s\n",errbuf); exit(1); }


	if(argc > 2)
	{		
		parse_file(argv[2], options);
		/* Lets try and compile the program.. non-optimized */
		if(pcap_compile(descr,&fcp,options,0,netp) == -1)
		{ fprintf(stderr,"[ERROR] Syntax error in the config file.\n"); exit(1); }

		/* set the compiled program as the filter */
		if(pcap_setfilter(descr,&fcp) == -1)
		{ fprintf(stderr,"[ERROR] Bad syntax in the config file.\n"); exit(1); }
	}
	fprintf(stdout, "[INFO] Connection with network devices successfully established.\n");
	/************************************* End of network components **************************************/

	/* Open log file if required */
#ifdef FILE_OUTPUT
//	if( (fp = fopen("/dev/null", "w")) == NULL ) {
	if( (fp = fopen("log.txt", "w")) == NULL ) {
		fprintf(stderr, "[ERROR] Error opening log file.\n");
		exit(-1);
	}
#endif

	/* Summary file for web interface */
	if( (web = fopen("/tmp/sniffweb.txt", "w")) == NULL ) {
		fprintf(stderr, "[ERROR] Could not open web interface file.\n");
		exit(-1);
	}
	fclose(web); // The file is all good to be used when required!
	
	/* Keys for shared memory */
	key = 3983;
	sumkey = 1283;

	/* Initialize the semaphore */
	if( (semid = initSem()) == -1 ) {
		fprintf(stderr, "[ERROR] Semaphore initialization failed.\n");
		exit(-1);
	}

	/* Create shared memory for packet dump */
	if( (shmid = shmget(key, SHMSZ, IPC_CREAT | 0666)) == -1 ) {
		fprintf(stderr, "[ERROR] Memory allocation failed.\n");
		exit(-1);
	}
	writer = (char*)shmat(shmid, NULL, 0);
	shm = writer;
	reader = writer;

	/* Size of summary shared memory */
	SUMSIZE = 2*sizeof(struct timeval) + sizeof(int) + NUM_MACHINES*sizeof(struct basket);

	/* 
	 * Create shared memory for summary 
	 * This is done here so that the parent process can clean all shared memory
	 */
	if( (sumid = shmget(sumkey, SUMSIZE, IPC_CREAT|0666)) == -1){
		fprintf(stderr, "[ERROR] Memory allocation for summary failed.\n");
		exit(-1);
	}
	smwrite = shmat(sumid, NULL, 0);
	smread = smwrite;
	
	/* Create the summary basket */
	if( (basket_pool = create_list((smwrite + 2*sizeof(struct timeval) + sizeof(int)), NUM_MACHINES*sizeof(struct basket))) == NULL ) {
		fprintf(stderr, "[ERROR] Error in summary basket memory allocation.\n");
	}

	/**
	 * Triple process architecture
	 * Spawn one more process to separate the tasks of packet capture and analysis
	 **/
	pid = fork();

	if( pid < 0 ) {
		fprintf(stderr, "[ERROR] Fork failed.\n");
		cleanUp();
		exit(-1);
	}
	else if( pid == 0 ) {
		/**
		 * $$Process No$$ 01
		 * This process dumps all the packets sniffed onto a shared memory
		 **/

		/* Catch SIGINT ctrl C signal from the keyboard */
		signal(SIGINT, cleanUp);
		
		fprintf(stdout, "[INFO] Started packet dump engine process. PID = %d\n", getpid());
		/* The loop that sniffs required number of packets */ 
		pcap_loop(descr,atoi(argv[1]),packet_handler,args);
		
		/* Wait for all packets to get analysed before shutting down */
		while(getSem(semid) != 0) {
		}

		/* Shut down */
		cleanUp();
	}
	else {

		/**
		 * Triple process architecture
		 * Spawn one more process for summarising the information periodically
		 **/
		
		/* Catch SIGINT ctrl C signal from the keyboard */
		signal(SIGINT, suicide);
		
		if( (pidchild = fork()) < 0 ) {
			fprintf(stderr, "[ERROR] Summary fork failed.\n");
			cleanUp();
			exit(-1);
		}

		if(pidchild == 0) {
			/**
			 * $$Process No$$ 02
			 * This process analyzes all the dump
			 **/

			/* Wait till the writer starts writing! */
			while( getSem(semid) <= 0 )
				sleep(0.01);

			/* Yippie! The machine starts to roll... */
			fprintf(stdout, "[INFO] Started packet dump analysis engine process. PID = %d\n", getpid());

			/* Start reading the packets dumped */
			analyze_dump();
		}
		else {
			/**
			 * $$Process No$$ 03
			 * Spawn one more process for summarising all the extracted information
			 **/
			fprintf(stdout, "[INFO] Started packet analysis summary engine process. PID = %d\n", getpid());
			/* Start summarising the analysis */
			summarise_analysis();
		}
	}
	return 0;
}
#endif
