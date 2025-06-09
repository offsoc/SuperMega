import logging
from model.defs import *

logger = logging.getLogger("Views")


class Settings():
    def __init__(self, project_name: str = "default"):
        self.project_name: str = project_name
        self.payload_path: FilePath = FilePath("")

        # Settings
        self.carrier_name: str = ""
        self.decoder_style: str = "xor_2"
        self.short_call_patching: bool = False

        self.plugin_antiemulation: str = "none"
        self.plugin_decoy: str = "none"
        self.plugin_guardrail: str = "none"
        self.plugin_guardrail_data_key: str = ""
        self.plugin_guardrail_data_value: str = ""
        self.plugin_virtualprotect: str = "standard"
        self.plugin_virtualprotect_data: str = ""

        self.dllfunc: str = ""  # For DLL injection

        # Anti-debugging
        self.sir_iteration_count: int = 5
        self.sir_alloc_count: int = 100

        # Injectable
        self.carrier_invoke_style: CarrierInvokeStyle = CarrierInvokeStyle.BackdoorCallInstr
        self.inject_exe_in: FilePath = FilePath("")
        self.inject_exe_out: FilePath = FilePath("")

        # Debug
        self.show_command_output: bool = False
        self.verify: bool = False
        self.try_start_final_infected_exe: bool = False
        self.cleanup_files_on_start: bool = True
        self.cleanup_files_on_exit: bool = True
        self.generate_asm_from_c: bool = True

        # More
        self.fix_missing_iat = True
        self.patch_show_window = True
        self.payload_location: PayloadLocation = PayloadLocation.DATA

        # directories and filenames
        self.main_dir: FilePath = FilePath("{}{}/".format(PATH_WEB_PROJECT, self.project_name))
        self.main_c_path: FilePath = FilePath(self.main_dir + "main.c")
        self.main_asm_path: FilePath = FilePath(self.main_dir + "main.asm")
        self.main_exe_path: FilePath = FilePath(self.main_dir + "main.exe")
        self.main_shc_path: FilePath = FilePath(self.main_dir + "main.bin")
        self.inject_exe_out: FilePath = FilePath("{}{}".format(
            self.main_dir, os.path.basename(self.inject_exe_in).replace(".exe", ".infected.exe")))


    def init_payload_injectable(self, shellcode: FilePath, injectable: FilePath, dll_func: str ):
        self.payload_path = FilePath(PATH_SHELLCODES + shellcode)
        if shellcode == "createfile.bin":
            self.verify = True
            self.try_start_final_infected_exe = False
        else:
            self.cleanup_files_on_exit = False
        
        self.inject_exe_in = FilePath(PATH_EXES + injectable)
        self.inject_exe_out = FilePath("{}{}".format(
            self.main_dir,
            os.path.basename(self.inject_exe_in).replace(".exe", ".infected.exe")
        ))

        self.dllfunc = dll_func