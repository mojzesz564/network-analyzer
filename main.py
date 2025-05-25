from analyzer.sniffer import start_sniffing
#from web.app import run_dashboard

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', default='Ethernet', help='Interface to sniff')
    parser.add_argument('--web-dashboard', action='store_true', help='Enable web dashboard')
    args = parser.parse_args()

    start_sniffing(args.iface)
#    if args.web_dashboard:
#        run_dashboard()