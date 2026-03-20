import json
import sys
from elfanalyzer import ELFAnalyzer

def injest(binary_path: str, output_path: str = "osint_output.json") -> dict:
   analyzer = ELFAnalyzer(binary_path)
   result = analyzer.analyze()

   osint = {
      "hashes": result["hashes"],
      "file_size": result["file_size"],
      "arch": result["arch"],
      "imports": result["imports"],
      "symbols": result["symbols"],
      "sections": result["sections"],
      "strings": result["strings"][:200],
      "security": result["security"],
      "entropy": result["entropy"],
      "static": result["static"],
      "iocs": {
         "verdict": result["iocs"]["verdict"],
	 "severity": result["iocs"]["severity"],
	 "counts": result["iocs"]["counts"],
 	 "hits": result["iocs"]["hits"],
      },
   }

   with open(output_path, "w") as f:
      json.dump(osint, f, indent=2)

   print(f"[+] Analysis complete: {binary_path}")
   print(f"    Verdict: {osint['iocs']['verdict']}")
   print(f"    Severity: {osint['iocs']['severity']}")
   print(f"    Saved to: {output_path}")

   return osint

if __name__ == "__main__":
   if len(sys.argv) < 2:
      print("Usage: python injest.py <path_to_elf_binary>")
      sys.exit(1)
   injest(sys.argv[1])
