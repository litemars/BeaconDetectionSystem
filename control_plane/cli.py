#!/usr/bin/env python3
"""
Beacon Detection CLI

Commands:
    status          Show system status (live/offline)
    beacons         Show detected beacons
    long-conns      Show long-standing connections
    connections     Show all tracked connections
    watch           Live monitoring mode (auto-refresh)

Examples:
    python3 -m control_plane.cli status
    python3 -m control_plane.cli beacons --min-score 0.7
    python3 -m control_plane.cli long-conns --min-duration 3600
    python3 -m control_plane.cli watch --interval 5
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ANSI color codes
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Foreground colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright foreground
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'


def supports_color():

    if os.getenv('NO_COLOR'):
        return False
    if os.getenv('FORCE_COLOR'):
        return True
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()


USE_COLOR = supports_color()


def c(text: str, *colors):

    if not USE_COLOR or not colors:
        return text
    return ''.join(colors) + str(text) + Colors.RESET


def clear_screen():

    os.system('cls' if os.name == 'nt' else 'clear')


def get_terminal_width():

    try:
        return os.get_terminal_size().columns
    except OSError:
        return 120


class BeaconCLI:
    
    BANNER = r"""
    ____                               ____       __            __ 
   / __ )___  ____ __________  ____   / __ \___  / /____  _____/ /_
  / __  / _ \/ __ `/ ___/ __ \/ __ \ / / / / _ \/ __/ _ \/ ___/ __/
 / /_/ /  __/ /_/ / /__/ /_/ / / / // /_/ /  __/ /_/  __/ /__/ /_  
/_____/\___/\__,_/\___/\____/_/ /_//_____/\___/\__/\___/\___/\__/  
                                                                   
    """
    
    def __init__(self, host: str = 'localhost', port: int = 9090):
        self.host = host
        self.port = port
        self.base_url = f'http://{host}:{port}'
    
    def _api_request(self, endpoint: str):

        try:
            url = f'{self.base_url}{endpoint}'
            req = Request(url, headers={'Accept': 'application/json'})
            with urlopen(req, timeout=5) as response:
                return json.loads(response.read().decode())
        except (URLError, HTTPError, json.JSONDecodeError) as e:
            return None
    
    def print_banner(self):

        print(c(self.BANNER, Colors.CYAN))
        print(c("  Real-time Network Beacon Detection System", Colors.DIM))
        print(c(f"  Server: {self.base_url}", Colors.DIM))
        print()
    
    def print_header(self, title: str):

        width = get_terminal_width()
        print()
        print(c("═" * width, Colors.BLUE))
        print(c(f"  {title}", Colors.BOLD, Colors.BRIGHT_WHITE))
        print(c("═" * width, Colors.BLUE))
        print()
    
    def print_table(self, headers, rows, 
                    col_widths = None):

        if not col_widths:
            # Calculate column widths
            col_widths = [len(h) for h in headers]
            for row in rows:
                for i, cell in enumerate(row):
                    if i < len(col_widths):
                        col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Print header
        header_line = "  "
        for i, h in enumerate(headers):
            header_line += c(h.ljust(col_widths[i] + 2), Colors.BOLD, Colors.BRIGHT_CYAN)
        print(header_line)
        
        # Print separator
        sep_line = "  "
        for w in col_widths:
            sep_line += c("-" * w + "  ", Colors.DIM)
        print(sep_line)
        
        # Print rows
        for row in rows:
            row_line = "  "
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    row_line += str(cell).ljust(col_widths[i] + 2)
            print(row_line)
    
    def format_score(self, score: float):

        pct = score * 100
        if score >= 0.9:
            return c(f"{pct:5.1f}%", Colors.BRIGHT_RED, Colors.BOLD)
        elif score >= 0.8:
            return c(f"{pct:5.1f}%", Colors.BRIGHT_YELLOW, Colors.BOLD)
        elif score >= 0.7:
            return c(f"{pct:5.1f}%", Colors.YELLOW)
        else:
            return c(f"{pct:5.1f}%", Colors.GREEN)
    
    def format_severity(self, score: float):

        if score >= 0.9:
            return c("CRITICAL", Colors.BG_RED, Colors.BRIGHT_WHITE, Colors.BOLD)
        elif score >= 0.8:
            return c("HIGH    ", Colors.BRIGHT_RED, Colors.BOLD)
        elif score >= 0.7:
            return c("MEDIUM  ", Colors.YELLOW)
        else:
            return c("LOW     ", Colors.GREEN)
    
    def format_duration(self, seconds: float):

        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        elif seconds < 86400:
            return f"{seconds/3600:.1f}h"
        else:
            return f"{seconds/86400:.1f}d"
    
    def format_count(self, count: int):

        if count >= 10000:
            return c(f"{count:,}", Colors.BRIGHT_RED)
        elif count >= 1000:
            return c(f"{count:,}", Colors.YELLOW)
        else:
            return f"{count:,}"
    
    def cmd_status(self):

        self.print_banner()
        self.print_header("SYSTEM STATUS")
        
        # Check health
        health = self._api_request('/api/v1/health')
        status = self._api_request('/api/v1/status')
        
        if not health or not status:
            print(c("  ✗ OFFLINE", Colors.BRIGHT_RED, Colors.BOLD))
            print(c(f"    Cannot connect to server at {self.base_url}", Colors.DIM))
            print()
            return False
        
        # System is live
        print(c("  ✓ LIVE", Colors.BRIGHT_GREEN, Colors.BOLD))
        print()
        
        # Print stats
        uptime = status.get('uptime_seconds', 0)
        uptime_str = self.format_duration(uptime) if uptime else 'N/A'
        
        stats = [
            ("Server", f"{self.host}:{self.port}"),
            ("Status", c("Running", Colors.GREEN)),
            ("Uptime", uptime_str),
            ("Events Received", f"{status.get('events_received', 0):,}"),
            ("Connection Pairs", f"{status.get('storage', {}).get('pairs_count', 0):,}"),
            ("Beacons Detected", f"{status.get('analyzer', {}).get('beacons_detected', 0):,}"),
            ("Alerts Generated", f"{status.get('alerter', {}).get('alerts_sent', 0):,}"),
            ("Analysis Runs", f"{status.get('analyzer', {}).get('analysis_runs', 0):,}"),
        ]
        
        for label, value in stats:
            print(f"  {c(label + ':', Colors.DIM):30} {value}")
        
        print()
        return True
    
    def cmd_beacons(self, min_score: float = 0.0, limit: int = 50, csv_output: bool = False):

        if not csv_output:
            self.print_banner()
            self.print_header("DETECTED BEACONS")
        
        data = self._api_request('/api/v1/beacons')
        if not data:
            if not csv_output:
                print(c("  ✗ Cannot connect to server", Colors.RED))
            return
        
        beacons = data.get('beacons', [])
        
        # Filter by score
        beacons = [b for b in beacons if b.get('combined_score', 0) >= min_score]
        
        # Sort by score descending
        beacons.sort(key=lambda x: x.get('combined_score', 0), reverse=True)
        
        # Limit results
        beacons = beacons[:limit]
        
        if not beacons:
            if not csv_output:
                print(c("  No beacons detected", Colors.DIM))
                print()
            return
        
        if csv_output:
            # CSV output
            print("Score,Severity,Source_IP,Source_Port,Dest_IP,Dest_Port,Protocol,Connections,Interval,Jitter")
            for b in beacons:
                score = b.get('combined_score', 0)
                severity = "CRITICAL" if score >= 0.9 else "HIGH" if score >= 0.8 else "MEDIUM" if score >= 0.7 else "LOW"
                interval = b.get('interval_stats', {}).get('mean', 0)
                jitter = b.get('interval_stats', {}).get('jitter', 0)
                print(f"{score:.4f},{severity},{b.get('src_ip', '-')},-,{b.get('dst_ip', '-')},{b.get('dst_port', '-')},{b.get('protocol', 'TCP')},{b.get('connection_count', 0)},{interval:.2f},{jitter:.2f}")
        else:
            # Table output
            print(f"  Found {c(str(len(beacons)), Colors.BOLD)} beacon(s) with score >= {min_score:.1%}")
            print()
            
            headers = ["SCORE", "SEVERITY", "SOURCE IP", "DEST IP", "PORT", "PROTO", "CONNS", "INTERVAL", "JITTER"]
            rows = []
            
            for b in beacons:
                score = b.get('combined_score', 0)
                interval = b.get('interval_stats', {}).get('mean', 0)
                jitter = b.get('interval_stats', {}).get('jitter', 0)
                
                rows.append([
                    self.format_score(score),
                    self.format_severity(score),
                    b.get('src_ip', '-'),
                    b.get('dst_ip', '-'),
                    str(b.get('dst_port', '-')),
                    b.get('protocol', 'TCP'),
                    self.format_count(b.get('connection_count', 0)),
                    f"{interval:.1f}s",
                    f"{jitter:.2f}s"
                ])
            
            self.print_table(headers, rows, [7, 10, 18, 18, 6, 5, 8, 10, 8])
            print()
    
    def cmd_long_connections(self, min_duration = 3600, limit = 50, csv_output = False):

        if not csv_output:
            self.print_banner()
            self.print_header("LONG CONNECTIONS")
        
        data = self._api_request(f'/api/v1/connections?limit=500')
        if not data:
            if not csv_output:
                print(c("  ✗ Cannot connect to server", Colors.RED))
            return
        
        pairs = data.get('pairs', [])
        
        # Filter by duration
        pairs = [p for p in pairs if p.get('duration_seconds', 0) >= min_duration]
        
        # Sort by duration descending
        pairs.sort(key=lambda x: x.get('duration_seconds', 0), reverse=True)
        
        # Limit results
        pairs = pairs[:limit]
        
        if not pairs:
            if not csv_output:
                print(c(f"  No connections longer than {self.format_duration(min_duration)}", Colors.DIM))
                print()
            return
        
        if csv_output:
            print("Duration,Source_IP,Dest_IP,Dest_Port,Protocol,Connections,First_Seen,Last_Seen")
            for p in pairs:
                duration = p.get('duration_seconds', 0)
                print(f"{duration:.0f},{p.get('src_ip', '-')},{p.get('dst_ip', '-')},{p.get('dst_port', '-')},{p.get('protocol', 'TCP')},{p.get('connection_count', 0)},{p.get('first_seen', '-')},{p.get('last_seen', '-')}")
        else:
            print(f"  Found {c(str(len(pairs)), Colors.BOLD)} connection(s) longer than {self.format_duration(min_duration)}")
            print()
            
            headers = ["DURATION", "SOURCE IP", "DEST IP", "PORT", "PROTO", "CONNS", "FIRST SEEN", "LAST SEEN"]
            rows = []
            
            for p in pairs:
                duration = p.get('duration_seconds', 0)
                first_seen = p.get('first_seen', '-')
                last_seen = p.get('last_seen', '-')
                
                # Format timestamps
                if first_seen and first_seen != '-':
                    try:
                        dt = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                        first_seen = dt.strftime('%Y-%m-%d %H:%M')
                    except:
                        pass
                
                if last_seen and last_seen != '-':
                    try:
                        dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                        last_seen = dt.strftime('%Y-%m-%d %H:%M')
                    except:
                        pass
                
                # Color code duration
                dur_str = self.format_duration(duration)
                if duration >= 86400:  # > 1 day
                    dur_str = c(dur_str, Colors.BRIGHT_RED, Colors.BOLD)
                elif duration >= 3600:  # > 1 hour
                    dur_str = c(dur_str, Colors.YELLOW)
                
                rows.append([
                    dur_str,
                    p.get('src_ip', '-'),
                    p.get('dst_ip', '-'),
                    str(p.get('dst_port', '-')),
                    p.get('protocol', 'TCP'),
                    str(p.get('connection_count', 0)),
                    first_seen,
                    last_seen
                ])
            
            self.print_table(headers, rows, [10, 18, 18, 6, 5, 8, 18, 18])
            print()
    
    def cmd_connections(self, limit: int = 100, csv_output: bool = False):

        if not csv_output:
            self.print_banner()
            self.print_header("TRACKED CONNECTIONS")
        
        data = self._api_request(f'/api/v1/connections?limit={limit}')
        if not data:
            if not csv_output:
                print(c("  ✗ Cannot connect to server", Colors.RED))
            return
        
        pairs = data.get('pairs', [])
        
        # Sort by connection count descending
        pairs.sort(key=lambda x: x.get('connection_count', 0), reverse=True)
        
        if not pairs:
            if not csv_output:
                print(c("  No connections tracked", Colors.DIM))
                print()
            return
        
        if csv_output:
            print("Source_IP,Dest_IP,Dest_Port,Protocol,Connections,Duration,First_Seen,Last_Seen")
            for p in pairs:
                print(f"{p.get('src_ip', '-')},{p.get('dst_ip', '-')},{p.get('dst_port', '-')},{p.get('protocol', 'TCP')},{p.get('connection_count', 0)},{p.get('duration_seconds', 0):.0f},{p.get('first_seen', '-')},{p.get('last_seen', '-')}")
        else:
            print(f"  Showing {c(str(len(pairs)), Colors.BOLD)} connection pair(s)")
            print()
            
            headers = ["SOURCE IP", "DEST IP", "PORT", "PROTO", "CONNS", "DURATION", "LAST SEEN"]
            rows = []
            
            for p in pairs[:limit]:
                duration = p.get('duration_seconds', 0)
                last_seen = p.get('last_seen', '-')
                
                if last_seen and last_seen != '-':
                    try:
                        dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                        last_seen = dt.strftime('%m-%d %H:%M')
                    except:
                        pass
                
                rows.append([
                    p.get('src_ip', '-'),
                    p.get('dst_ip', '-'),
                    str(p.get('dst_port', '-')),
                    p.get('protocol', 'TCP'),
                    self.format_count(p.get('connection_count', 0)),
                    self.format_duration(duration),
                    last_seen
                ])
            
            self.print_table(headers, rows, [18, 18, 6, 5, 8, 10, 14])
            print()
    
    def cmd_watch(self, interval: int = 5):
        try:
            while True:
                clear_screen()
                self.print_banner()
                
                # Check if live
                health = self._api_request('/api/v1/health')
                status = self._api_request('/api/v1/status')
                
                if not health or not status:
                    print(c("  ✗ SYSTEM OFFLINE", Colors.BRIGHT_RED, Colors.BOLD))
                    print(c(f"    Waiting for connection to {self.base_url}...", Colors.DIM))
                else:
                    # Status line
                    uptime = status.get('uptime_seconds', 0)
                    events = status.get('events_received', 0)
                    pairs = status.get('storage', {}).get('pairs_count', 0)
                    beacons_count = status.get('analyzer', {}).get('beacons_detected', 0)
                    
                    print(f"  {c('●', Colors.BRIGHT_GREEN)} {c('LIVE', Colors.BOLD, Colors.BRIGHT_GREEN)}  │  "
                          f"Uptime: {self.format_duration(uptime)}  │  "
                          f"Events: {events:,}  │  "
                          f"Pairs: {pairs:,}  │  "
                          f"Beacons: {c(str(beacons_count), Colors.YELLOW if beacons_count else Colors.GREEN)}")
                    
                    # Show beacons
                    self.print_header("DETECTED BEACONS (Score >= 70%)")
                    
                    data = self._api_request('/api/v1/beacons')
                    if data:
                        beacons = [b for b in data.get('beacons', []) if b.get('combined_score', 0) >= 0.7]
                        beacons.sort(key=lambda x: x.get('combined_score', 0), reverse=True)
                        
                        if beacons:
                            headers = ["SCORE", "SEVERITY", "SOURCE IP", "→", "DEST IP:PORT", "CONNS", "INTERVAL"]
                            rows = []
                            
                            for b in beacons[:15]:
                                score = b.get('combined_score', 0)
                                interval_val = b.get('interval_stats', {}).get('mean', 0)
                                dest = f"{b.get('dst_ip', '-')}:{b.get('dst_port', '-')}"
                                
                                rows.append([
                                    self.format_score(score),
                                    self.format_severity(score),
                                    b.get('src_ip', '-'),
                                    c("→", Colors.DIM),
                                    dest,
                                    str(b.get('connection_count', 0)),
                                    f"{interval_val:.1f}s"
                                ])
                            
                            self.print_table(headers, rows, [7, 10, 18, 2, 25, 8, 10])
                        else:
                            print(c("  No high-confidence beacons detected", Colors.DIM))
                    
                    # Show long connections
                    self.print_header("LONG CONNECTIONS (> 1 hour)")
                    
                    data = self._api_request('/api/v1/connections?limit=200')
                    if data:
                        long_conns = [p for p in data.get('pairs', []) if p.get('duration_seconds', 0) >= 3600]
                        long_conns.sort(key=lambda x: x.get('duration_seconds', 0), reverse=True)
                        
                        if long_conns:
                            headers = ["DURATION", "SOURCE IP", "→", "DEST IP:PORT", "CONNS"]
                            rows = []
                            
                            for p in long_conns[:10]:
                                duration = p.get('duration_seconds', 0)
                                dur_str = self.format_duration(duration)
                                if duration >= 86400:
                                    dur_str = c(dur_str, Colors.BRIGHT_RED, Colors.BOLD)
                                elif duration >= 3600:
                                    dur_str = c(dur_str, Colors.YELLOW)
                                
                                dest = f"{p.get('dst_ip', '-')}:{p.get('dst_port', '-')}"
                                
                                rows.append([
                                    dur_str,
                                    p.get('src_ip', '-'),
                                    c("→", Colors.DIM),
                                    dest,
                                    str(p.get('connection_count', 0))
                                ])
                            
                            self.print_table(headers, rows, [10, 18, 2, 25, 8])
                        else:
                            print(c("  No long connections detected", Colors.DIM))
                
                print()
                print(c(f"  Refreshing every {interval}s... Press Ctrl+C to exit", Colors.DIM))
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print()
            print(c("  Monitoring stopped", Colors.DIM))
            print()


def main():
    parser = argparse.ArgumentParser(
        description='Beacon Detection CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s status                          Show system status
  %(prog)s beacons                         Show all detected beacons
  %(prog)s beacons --min-score 0.8         Show beacons with score >= 80%%
  %(prog)s beacons --csv                   Output beacons as CSV
  %(prog)s long-conns                      Show connections > 1 hour
  %(prog)s long-conns --min-duration 7200  Show connections > 2 hours
  %(prog)s watch                           Live monitoring mode
  %(prog)s watch --interval 10             Refresh every 10 seconds
        '''
    )
    
    parser.add_argument('--host', default='localhost',
                        help='Control plane host (default: localhost)')
    parser.add_argument('--port', type=int, default=9090,
                        help='Control plane port (default: 9090)')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Status command
    subparsers.add_parser('status', help='Show system status')
    
    # Beacons command
    beacons_parser = subparsers.add_parser('beacons', help='Show detected beacons')
    beacons_parser.add_argument('--min-score', type=float, default=0.0,
                                help='Minimum beacon score (0.0-1.0)')
    beacons_parser.add_argument('--limit', type=int, default=50,
                                help='Maximum results to show')
    beacons_parser.add_argument('--csv', '-o', action='store_true',
                                help='Output as CSV')
    
    # Long connections command
    long_parser = subparsers.add_parser('long-conns', help='Show long connections')
    long_parser.add_argument('--min-duration', type=int, default=3600,
                            help='Minimum duration in seconds (default: 3600)')
    long_parser.add_argument('--limit', type=int, default=50,
                            help='Maximum results to show')
    long_parser.add_argument('--csv', '-o', action='store_true',
                            help='Output as CSV')
    
    # Connections command
    conns_parser = subparsers.add_parser('connections', help='Show all connections')
    conns_parser.add_argument('--limit', type=int, default=100,
                             help='Maximum results to show')
    conns_parser.add_argument('--csv', '-o', action='store_true',
                             help='Output as CSV')
    
    # Watch command
    watch_parser = subparsers.add_parser('watch', help='Live monitoring mode')
    watch_parser.add_argument('--interval', type=int, default=5,
                             help='Refresh interval in seconds')
    
    args = parser.parse_args()
    
    # Handle no-color flag
    global USE_COLOR
    if args.no_color:
        USE_COLOR = False
    
    # Create CLI instance
    cli = BeaconCLI(host=args.host, port=args.port)
    
    # Execute command
    if args.command == 'status' or args.command is None:
        cli.cmd_status()
    elif args.command == 'beacons':
        cli.cmd_beacons(min_score=args.min_score, limit=args.limit, csv_output=args.csv)
    elif args.command == 'long-conns':
        cli.cmd_long_connections(min_duration=args.min_duration, limit=args.limit, csv_output=args.csv)
    elif args.command == 'connections':
        cli.cmd_connections(limit=args.limit, csv_output=args.csv)
    elif args.command == 'watch':
        cli.cmd_watch(interval=args.interval)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
