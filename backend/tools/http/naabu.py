"""naabu — port scanning."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

SERVICES = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
            143:"IMAP",443:"HTTPS",445:"SMB",1433:"MSSQL",3306:"MySQL",
            3389:"RDP",5432:"PostgreSQL",5900:"VNC",6379:"Redis",
            8080:"HTTP-Alt",8443:"HTTPS-Alt",27017:"MongoDB"}

class NaabuTool(BaseTool):
    name = "naabu"
    category = ToolCategory.PORT
    description = "Port scanning — top 1000 ports via naabu"
    parallel_group = "http"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        alive_file = out_dir / "probe_candidates.txt"
        if not alive_file.exists():
            return RunResult("", "No probe_candidates.txt", 1, 0)
        outfile = out_dir / "naabu.txt"
        return await self._exec([
            "naabu", "-silent", "-list", str(alive_file),
            "-top-ports", "1000", "-o", str(outfile),
        ], timeout=900)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        rows = []
        lines = result.lines or self._read_lines(self.output_dir / domain / "naabu.txt")
        for line in lines:
            if ":" in line:
                host, _, port_str = line.rpartition(":")
                try:
                    port = int(port_str)
                    rows.append({"host": host.strip(), "port": port,
                                 "service": SERVICES.get(port, ""),
                                 "state": "tcp_reachable", "source": "naabu"})
                except ValueError:
                    pass
        return rows
