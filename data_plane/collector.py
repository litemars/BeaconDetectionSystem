#!/usr/bin/env python3
"""
Data Plane Collector for eBPF Beaconing Detection System
Usage:
    sudo python3 -m data_plane.collector --config config/config.yaml --interface eth0
"""

import argparse
import ctypes
import logging
import os
import signal
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Dict

import yaml

# BCC imports - requires bcc-tools to be installed
try:
    from bcc import BPF
except ImportError:
    print("ERROR: BCC (BPF Compiler Collection) is not installed.")
    print("Install with: sudo apt-get install bpfcc-tools python3-bcc")
    sys.exit(1)

from .exporter import ExporterConfig, SyncTelemetryExporter
from .telemetry import (
    ConnectionEvent,
    ConnectionEventCType,
    DataPlaneStats,
    TelemetryBuffer,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("beacon_detect.data_plane.collector")


class DataPlaneCollector:
    """
    Main data plane collector class.

    Responsible for:
    - Loading and managing the eBPF program
    - Processing events from the ring buffer
    - Managing the telemetry buffer and export schedule
    """

    # Path to the eBPF program source
    EBPF_PROGRAM_PATH = Path(__file__).parent / "ebpf_program.c"

    def __init__(self, interface: str, config: Dict, node_id: str = None):

        self.interface = interface
        self.config = config
        self.node_id = node_id or self._generate_node_id()

        # eBPF components
        self._bpf = None

        # Telemetry components
        dp_config = config.get("data_plane", {})
        self._buffer = TelemetryBuffer(
            max_size=dp_config.get("max_buffer_size", 100000)
        )

        # Exporter configuration
        exporter_config = ExporterConfig(
            control_plane_host=dp_config.get("control_plane_host", "127.0.0.1"),
            control_plane_port=dp_config.get("control_plane_port", 9090),
            connection_timeout=dp_config.get("connection_timeout", 10.0),
            node_id=self.node_id,
        )
        self._exporter = SyncTelemetryExporter(exporter_config)

        # Export timing
        self._export_interval = dp_config.get("export_interval", 60)
        self._last_export_time = time.time()

        # Statistics
        self._stats = DataPlaneStats()

        # Control flags
        self._running = False
        self._shutdown_event = threading.Event()

        logger.info(
            f"DataPlaneCollector initialized: interface={interface}, "
            f"node_id={self.node_id}, export_interval={self._export_interval}s"
        )

    def _generate_node_id(self):
        import socket

        hostname = socket.gethostname()
        unique_suffix = uuid.uuid4().hex[:8]
        return f"dp-{hostname}-{unique_suffix}"

    def _load_ebpf_program(self):

        logger.info(f"Loading eBPF program from {self.EBPF_PROGRAM_PATH}")

        # Read the eBPF program source
        with open(self.EBPF_PROGRAM_PATH, "r") as f:
            bpf_source = f.read()

        # Apply configuration flags
        dp_config = self.config.get("data_plane", {})
        if not dp_config.get("track_tcp", True):
            bpf_source = bpf_source.replace(
                "#define TRACK_TCP 1", "#define TRACK_TCP 0"
            )
        if not dp_config.get("track_udp", True):
            bpf_source = bpf_source.replace(
                "#define TRACK_UDP 1", "#define TRACK_UDP 0"
            )

        # Compile the BPF program
        try:
            bpf = BPF(text=bpf_source, cflags=["-Wno-macro-redefined"])
            logger.info("eBPF program compiled successfully")
            return bpf
        except Exception as e:
            logger.error(f"Failed to compile eBPF program: {e}")
            raise

    def _attach_ebpf_program(self):

        logger.info(f"Attaching eBPF program to interface {self.interface}")

        # Try XDP first (best performance), fall back to TC
        try:
            # Attach XDP program
            fn = self._bpf.load_func("xdp_connection_tracker", BPF.XDP)
            self._bpf.attach_xdp(self.interface, fn, 0)
            logger.info(f"Attached XDP program to {self.interface}")
            self._attachment_mode = "xdp"
        except Exception as e:
            logger.warning(f"XDP attachment failed, trying TC: {e}")

            # Fall back to TC (Traffic Control)
            try:
                # Attach TC ingress
                fn_ingress = self._bpf.load_func("tc_ingress_tracker", BPF.SCHED_CLS)
                self._bpf.attach_raw_socket(fn_ingress, self.interface)

                logger.info(f"Attached TC program to {self.interface}")
                self._attachment_mode = "tc"
            except Exception as e2:
                logger.error(f"Failed to attach eBPF program: {e2}")
                raise RuntimeError(f"Could not attach eBPF program: {e2}")

    def _detach_ebpf_program(self):
        if self._bpf and hasattr(self, "_attachment_mode"):
            try:
                if self._attachment_mode == "xdp":
                    self._bpf.remove_xdp(self.interface, 0)
                logger.info(f"Detached eBPF program from {self.interface}")
            except Exception as e:
                logger.warning(f"Error detaching eBPF program: {e}")

    def _setup_ring_buffer(self):

        def ring_buffer_callback(ctx, data, size):

            try:
                # Cast the raw data to our event structure
                event = ctypes.cast(data, ctypes.POINTER(ConnectionEventCType)).contents

                # Convert to Python object
                conn_event = ConnectionEvent.from_ctype(event, self.node_id)

                # Apply whitelist filtering
                if self._should_filter(conn_event):
                    return

                # Add to buffer
                if not self._buffer.add(conn_event):
                    logger.warning("Buffer overflow, events being dropped")

            except Exception as e:
                logger.error(f"Error processing ring buffer event: {e}")

        # Get the ring buffer and set up polling
        self._bpf["events"].open_ring_buffer(ring_buffer_callback)
        logger.info("Ring buffer callback configured")

    def _should_filter(self, event: ConnectionEvent):

        whitelist = self.config.get("whitelist", {})

        # Check source IP whitelist
        if event.src_ip in whitelist.get("source_ips", []):
            return True

        # Check destination IP whitelist
        if event.dst_ip in whitelist.get("destination_ips", []):
            return True

        # Check port whitelist
        if event.dst_port in whitelist.get("ports", []):
            return True

        # Check specific pairs
        pair_key = f"{event.src_ip}:{event.dst_ip}:{event.dst_port}"
        if pair_key in whitelist.get("pairs", []):
            return True

        return False

    def _read_stats(self):

        try:
            stats_map = self._bpf["stats"]
            self._stats.packets_total = stats_map[ctypes.c_int(0)].value
            self._stats.packets_ipv4 = stats_map[ctypes.c_int(1)].value
            self._stats.packets_tcp = stats_map[ctypes.c_int(2)].value
            self._stats.packets_udp = stats_map[ctypes.c_int(3)].value
            self._stats.events_submitted = stats_map[ctypes.c_int(4)].value
            self._stats.events_dropped = stats_map[ctypes.c_int(5)].value
            self._stats.dedup_hits = stats_map[ctypes.c_int(6)].value
            self._stats.parse_errors = stats_map[ctypes.c_int(7)].value
            self._stats.events_buffered = self._buffer.size
        except Exception as e:
            logger.warning(f"Error reading stats: {e}")

    def _export_telemetry(self):

        events = self._buffer.drain()

        if not events:
            logger.debug("No events to export")
            return

        logger.info(f"Exporting {len(events)} events to control plane")

        try:
            success = self._exporter.export_events(events)
            if success:
                self._stats.batches_sent += 1
                logger.info(f"Successfully exported {len(events)} events")
            else:
                self._stats.batches_failed += 1
                logger.error("Failed to export telemetry batch")
                # Re-add events to buffer on failure (if there's space)
                self._buffer.add_batch(events)
        except Exception as e:
            self._stats.batches_failed += 1
            logger.error(f"Export error: {e}")
            # Re-add events to buffer
            self._buffer.add_batch(events)

    def start(self):

        logger.info("Starting data plane collector...")

        # Check root privileges
        if os.geteuid() != 0:
            raise PermissionError("Root privileges required for eBPF")

        # Load and attach eBPF program
        self._bpf = self._load_ebpf_program()
        self._attach_ebpf_program()
        self._setup_ring_buffer()

        # Start exporter
        self._exporter.start()

        self._running = True
        self._last_export_time = time.time()

        logger.info("Data plane collector started")

    def run(self):

        if not self._running:
            self.start()

        logger.info("Entering main event loop")

        try:
            while not self._shutdown_event.is_set():
                # Poll ring buffer for new events (100ms timeout)
                self._bpf.ring_buffer_poll(100)

                # Check if it's time to export
                current_time = time.time()
                if current_time - self._last_export_time >= self._export_interval:
                    self._read_stats()
                    self._export_telemetry()
                    self._last_export_time = current_time

                    # Log statistics
                    logger.info(f"Stats: {self._stats}")

        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        finally:
            self.stop()

    def stop(self):

        logger.info("Stopping data plane collector...")

        self._shutdown_event.set()
        self._running = False

        # Final export of any remaining events
        if self._buffer.size > 0:
            logger.info("Exporting remaining buffered events...")
            self._export_telemetry()

        # Stop exporter
        self._exporter.stop()

        # Detach and cleanup eBPF
        self._detach_ebpf_program()

        if self._bpf:
            self._bpf = None

        logger.info("Data plane collector stopped")

    @property
    def statistics(self):

        self._read_stats()
        return {
            "node_id": self.node_id,
            "interface": self.interface,
            "running": self._running,
            "ebpf_stats": self._stats.to_dict(),
            "exporter_stats": self._exporter.statistics,
            "buffer_size": self._buffer.size,
            "buffer_overflow": self._buffer.overflow_count,
        }


def load_config(config_path: str):

    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def setup_signal_handlers(collector):

    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, initiating shutdown...")
        collector.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def main():

    parser = argparse.ArgumentParser(
        description="eBPF Beaconing Detection - Data Plane Collector"
    )
    parser.add_argument(
        "-c", "--config", required=True, help="Path to configuration file"
    )
    parser.add_argument(
        "-i", "--interface", help="Network interface to monitor (overrides config)"
    )
    parser.add_argument(
        "-n",
        "--node-id",
        help="Unique node identifier (auto-generated if not provided)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

    # Determine interface
    interface = args.interface or config.get("data_plane", {}).get("interface")
    if not interface:
        logger.error("Network interface not specified")
        sys.exit(1)

    # Create and run collector
    try:
        collector = DataPlaneCollector(
            interface=interface, config=config, node_id=args.node_id
        )

        setup_signal_handlers(collector)

        collector.run()

    except PermissionError:
        logger.error("Root privileges required. Run with sudo.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
