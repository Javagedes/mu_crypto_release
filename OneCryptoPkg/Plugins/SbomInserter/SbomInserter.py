import io
import logging
import os
import tempfile

from pathlib import Path
from string import Template

from edk2toolext.environment.plugintypes.uefi_helper_plugin import IUefiHelperPlugin, HelperFunctions
from edk2toollib.utility_functions import RunCmd

TEMPLATE_PATH = Path(__file__).parent / "sbom.ini.template"

class SbomInserter(IUefiHelperPlugin):

    def RegisterHelpers(self, obj: HelperFunctions):
        fp = os.path.abspath(__file__)
        obj.Register("InsertSbomSection", SbomInserter.InsertSbomSection, fp)

    @staticmethod
    def InsertSbomSection(efi_file_path, sbom_data: dict) -> bool:
        """Helper function to insert an .sbom section into a PE/COFF binary."""
        
        template = Template(TEMPLATE_PATH.read_text())
        result = template.substitute(**sbom_data)
        
        with tempfile.NamedTemporaryFile(suffix=".ini") as temp_file:
            temp_file.write(result.encode())
            temp_file.flush()
            
            cmd = "uswid"
            args = ""
            args += f"--load {temp_file.name}"
            args += f" --save {str(efi_file_path)}"
            if "X64" in str(efi_file_path):
                args += f" --objcopy /usr/bin/objcopy"
            else:
                args += f" --objcopy /usr/bin/llvm-objcopy"

            result = io.StringIO()
            ret = RunCmd(cmd, args, outstream = result)
            if ret != 0:
                logging.error(result.getvalue())
                return False

            args = ""
            args += f"--load {temp_file.name}"
            args += f" --save {str(efi_file_path.with_suffix('.uswid'))}"
            args += f" --objcopy /usr/bin/llvm-objcopy"
            
            result = io.StringIO()
            ret = RunCmd(cmd, args, outstream = result)
            if ret != 0:
                logging.error(result.getvalue())
                return False
            return True
