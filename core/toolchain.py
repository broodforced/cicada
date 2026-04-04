## core/toolchain.py — unified tool execution

import subprocess
import json
import shutil
import re
from typing import Optional


class ToolChain:

	@staticmethod
	def available(name):
		return shutil.which(name) is not None

	@staticmethod
	def run(cmd, timeout=300, json_output=False, input_data=None):
		try:
			result = subprocess.run(
				cmd,
				capture_output=True,
				text=True,
				timeout=timeout,
				input=input_data,
			)
			stdout = result.stdout.strip()
			stderr = result.stderr.strip()

			if json_output and stdout:
				return ToolChain._parse_jsonl(stdout)

			return {
				"success": result.returncode == 0,
				"stdout": stdout,
				"stderr": stderr,
				"returncode": result.returncode,
			}
		except subprocess.TimeoutExpired:
			return {"success": False, "error": f"timeout after {timeout}s", "stdout": "", "stderr": ""}
		except FileNotFoundError:
			tool = cmd[0] if cmd else "unknown"
			return {"success": False, "error": f"{tool} not found", "stdout": "", "stderr": ""}
		except Exception as e:
			return {"success": False, "error": str(e), "stdout": "", "stderr": ""}

	@staticmethod
	def _parse_jsonl(raw):
		results = []
		for line in raw.splitlines():
			line = line.strip()
			if not line:
				continue
			try:
				results.append(json.loads(line))
			except json.JSONDecodeError:
				continue
		return results

	@staticmethod
	def run_stream(cmd, callback, timeout=600):
		try:
			proc = subprocess.Popen(
				cmd,
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE,
				text=True,
			)
			for line in proc.stdout:
				line = line.strip()
				if line:
					callback(line)
			proc.wait(timeout=timeout)
			return {"success": proc.returncode == 0}
		except subprocess.TimeoutExpired:
			proc.kill()
			return {"success": False, "error": "timeout"}
		except Exception as e:
			return {"success": False, "error": str(e)}

	@staticmethod
	def strip_ansi(text):
		return re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])').sub('', text)
