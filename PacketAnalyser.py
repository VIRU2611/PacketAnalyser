from scapy.all import *
import argparse
import sys

# Getting command line arguments
parser = argparse.ArgumentParser(description='network packet analyzer')
parser.add_argument('-d', '--destination_address', action="store_true", help='destination address', dest='d_add')
parser.add_argument('-s', '--source_address', action="store_true", help='source address', dest='s_add')
parser.add_argument('-dp', '--destination_port', action="store_true", help='destination port', dest='dp')
parser.add_argument('-sp', '--source_port', action="store_true", help='source port', dest='sp')
parser.add_argument('-p', '--protocol', action="store_true", help='protocol', dest='p')
parser.add_argument('-o', '--write_to_the_file', help='save the output', dest='ext')
args = parser.parse_args()


# Check if the user provided at least one argument

if not any([args.d_add, args.s_add, args.dp, args.sp,args.p]):
    # If no arguments were provided, print help and terminate.
    print("please provide atleast one argument")
    parser.print_help()
    exit(0)



def packet_handler(packet):
    out=[]
    if IP in packet:
        if args.s_add:
            src_ip = packet[IP].src
            out.append(f"|Source IP:{src_ip}")

        if args.d_add:
            dst_ip = packet[IP].dst
            out.append(f"|Destination IP:{dst_ip}")

        if TCP in packet:
            if args.sp:
                src_port = packet[TCP].sport
                out.append(f"|Source Port:{src_port}")

            if args.dp:
                dst_port = packet[TCP].dport
                out.append(f"|Destination Port:{dst_port}")

            payload = str(packet[TCP].payload)

            # Checking the protocol of the packet
            protocol = 'TCP'
            if args.p:
                out.append(f"|Protocol:{protocol}")

        elif UDP in packet:
            if args.sp:
                src_port = packet[UDP].sport
                out.append(f"|Source Port:{src_port}")
                

            if args.dp:
                dst_port = packet[UDP].dport
                out.append(f"|Destination Port:{dst_port}")

            payload = str(packet[UDP].payload)

            # Checking the protocol of the packet
            protocol = 'UDP'
            if args.p:
                out.append(f"|Protocol:{protocol}")
        else:
            if args.sp:
                out.append("|Source Port: Not Known")
            if args.dp:
                out.append("|Destination Port:Not Known")
            if args.p:  
                out.append("|Protocol:Not Known")        

        # Check if the user wants to save the output to the file
        if args.ext:
            print(args)
            save(out)
            
        print(''.join(out),'\n')
        

# Function to save the output to the file
def save(out):
    with open(f'{args.ext}', 'a') as f:
        f.write(''.join(out))
        f.write('\n')

def main():
    print("Starting Network Packet Analyzer...")
    try:
        sniff(prn=packet_handler, filter="ip")
           
    except KeyboardInterrupt:
        print("User interrupted the program.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

