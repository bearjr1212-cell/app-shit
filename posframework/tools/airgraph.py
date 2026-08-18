"""
Airgraph-NG Integration
────────────────────────
Visualization of client/AP relationships from airodump-ng captures:
  - CAPR (Client to AP Relationship) graph generation
  - CPG (Common Probe Graph) generation
  - Processes airodump-ng CSV output files
  - Produces PNG/SVG graph images for analysis

Airgraph-ng is part of the aircrack-ng suite and generates visual
representations of wireless network relationships. It helps identify
which clients are connected to which APs and what networks clients
are probing for.
"""

import os
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from posframework.config import log
from posframework.tools import is_available, which, run_tool


@dataclass
class GraphResult:
    """Result from an airgraph-ng graph generation."""
    output_file: str
    graph_type: str
    input_file: str
    success: bool
    error: str = ""
    nodes: int = 0
    edges: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary for live vector loading."""
        return {
            "output_file": self.output_file,
            "graph_type": self.graph_type,
            "input_file": self.input_file,
            "success": self.success,
            "error": self.error,
            "nodes": self.nodes,
            "edges": self.edges,
        }


class AirgraphNG:
    """
    Airgraph-ng wrapper for generating client/AP relationship visualizations.

    Processes airodump-ng CSV capture files and produces graph images
    showing relationships between access points and connected clients.

    Usage:
        ag = AirgraphNG()
        result = ag.generate_graph(
            csv_file="/tmp/capture-01.csv",
            output_file="/tmp/network_map.png",
            graph_type="CAPR"
        )
        if result.success:
            print(f"Graph saved to {result.output_file}")

        # Common Probe Graph (shows what SSIDs clients are probing for)
        result = ag.generate_graph(
            csv_file="/tmp/capture-01.csv",
            output_file="/tmp/probes.png",
            graph_type="CPG"
        )
    """

    VALID_GRAPH_TYPES = ("CAPR", "CPG")

    def __init__(self):
        if not is_available("airgraph-ng"):
            raise FileNotFoundError(
                "airgraph-ng not installed. Install: apt-get install aircrack-ng"
            )

    def generate_graph(
        self,
        csv_file: str,
        output_file: str,
        graph_type: str = "CAPR",
    ) -> GraphResult:
        """
        Generate a network relationship graph from airodump-ng CSV data.

        Args:
            csv_file: Path to airodump-ng CSV capture file.
            output_file: Path for the output graph image (PNG).
            graph_type: Type of graph to generate:
                - 'CAPR': Client to AP Relationship (who is connected to what)
                - 'CPG': Common Probe Graph (what SSIDs clients are looking for)

        Returns:
            GraphResult with success status and output file path.
        """
        # Validate graph type
        if graph_type.upper() not in self.VALID_GRAPH_TYPES:
            return GraphResult(
                output_file=output_file,
                graph_type=graph_type,
                input_file=csv_file,
                success=False,
                error=f"Invalid graph type '{graph_type}'. Use: {self.VALID_GRAPH_TYPES}",
            )

        # Validate input file
        if not os.path.isfile(csv_file):
            return GraphResult(
                output_file=output_file,
                graph_type=graph_type,
                input_file=csv_file,
                success=False,
                error=f"Input CSV file not found: {csv_file}",
            )

        graph_type = graph_type.upper()

        # Build airgraph-ng command
        # airgraph-ng -i <csv_file> -o <output_file> -g <graph_type>
        args = [
            "-i", csv_file,
            "-o", output_file,
            "-g", graph_type,
        ]

        log.info(f"airgraph-ng: Generating {graph_type} graph from {csv_file}")
        log.debug(f"airgraph-ng: output -> {output_file}")

        try:
            result = run_tool("airgraph-ng", args, timeout=60)

            if result.returncode == 0:
                # Count nodes/edges from output if available
                nodes, edges = self._parse_graph_stats(result.stdout)
                log.info(f"airgraph-ng: Graph generated ({nodes} nodes, {edges} edges)")
                return GraphResult(
                    output_file=output_file,
                    graph_type=graph_type,
                    input_file=csv_file,
                    success=True,
                    nodes=nodes,
                    edges=edges,
                )
            else:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                log.error(f"airgraph-ng failed: {error_msg}")
                return GraphResult(
                    output_file=output_file,
                    graph_type=graph_type,
                    input_file=csv_file,
                    success=False,
                    error=error_msg,
                )
        except FileNotFoundError:
            return GraphResult(
                output_file=output_file,
                graph_type=graph_type,
                input_file=csv_file,
                success=False,
                error="airgraph-ng binary not found",
            )
        except subprocess.TimeoutExpired:
            return GraphResult(
                output_file=output_file,
                graph_type=graph_type,
                input_file=csv_file,
                success=False,
                error="airgraph-ng timed out (>60s)",
            )

    def generate_capr(self, csv_file: str, output_file: str) -> GraphResult:
        """
        Convenience method: Generate Client to AP Relationship graph.

        Args:
            csv_file: Path to airodump-ng CSV.
            output_file: Output PNG path.

        Returns:
            GraphResult.
        """
        return self.generate_graph(csv_file, output_file, graph_type="CAPR")

    def generate_cpg(self, csv_file: str, output_file: str) -> GraphResult:
        """
        Convenience method: Generate Common Probe Graph.

        Args:
            csv_file: Path to airodump-ng CSV.
            output_file: Output PNG path.

        Returns:
            GraphResult.
        """
        return self.generate_graph(csv_file, output_file, graph_type="CPG")

    def get_available_csv_files(self, search_dir: str = "/tmp") -> List[str]:
        """
        Find airodump-ng CSV files in a directory for live vector loading.

        Args:
            search_dir: Directory to search for CSV files.

        Returns:
            List of paths to airodump CSV files.
        """
        csv_files = []
        try:
            for f in os.listdir(search_dir):
                if f.endswith(".csv") and ("airodump" in f or "-01.csv" in f):
                    csv_files.append(os.path.join(search_dir, f))
        except OSError:
            pass
        return sorted(csv_files)

    @staticmethod
    def _parse_graph_stats(stdout: str) -> tuple:
        """
        Parse airgraph-ng stdout for graph statistics.

        Args:
            stdout: Standard output from airgraph-ng.

        Returns:
            Tuple of (nodes, edges).
        """
        nodes = 0
        edges = 0
        if not stdout:
            return nodes, edges

        for line in stdout.split("\n"):
            line_lower = line.lower()
            if "node" in line_lower:
                # Try to extract number
                parts = line.split()
                for p in parts:
                    if p.isdigit():
                        nodes = int(p)
                        break
            if "edge" in line_lower or "link" in line_lower:
                parts = line.split()
                for p in parts:
                    if p.isdigit():
                        edges = int(p)
                        break
        return nodes, edges
