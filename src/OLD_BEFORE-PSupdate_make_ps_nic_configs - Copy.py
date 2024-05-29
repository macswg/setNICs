import pygsheets
from typing import List, Type
from dataclasses import dataclass, field
import pandas as pd
import numpy as np
import re
import logging

# Logging info
logging.basicConfig(filename='ignore_log_powershellExporNIC.md',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# disables logging up to a level specified when uncommented
# logging.disabled(logging.ERROR)
message = "\n \n *** START OF SCRIPT ***"
logging.info(message)


@dataclass
class NICInfo:
    """
    data class to store network interface card (NIC) information.
    Attributes:
        name (str): The name of the NIC.
        ip_addr (str): the ip address of the NIC.
        subnet (str): the subnet mask to assign to the NIC
        gateway (str): the default gateway to assign to the NIC
    """
    nic_slc: tuple
    name: str
    ip_addr: str
    subnet: str
    gateway: str


@dataclass
class MachineInf:
    """
    data class to store machine information
    Attributes:
        m_i (int): the machine index (input index) of the machine row from the
            dataframe. I added this to the class to ensure pulling the correct
            row when adding NICs.
        name (str): The name of the machine.
        nics (List[NICInfo]): A list of NIC info associated with the machine.
        num_of_nics (int): calculated by an external function and then used
            for nic slicing and to error check against final nic list.
    """
    m_i: int
    name: str = field(default_factory=str)
    nics: List[NICInfo] = field(default_factory=list)
    num_of_nics: int = field(default_factory=int)

    def add_nic(self, df: pd.DataFrame, slices: tuple) -> None:
        """
        adds a machine to the instance of MachineInfo from a string of data.
        """
        start, end = slices
        sliced_df = df.iloc[:, start: end]
        # print(sliced_df)

        m_i_adjust = self.m_i - 1

        new_nic = NICInfo(
            nic_slc=slices,
            name=sliced_df.at[m_i_adjust, 'name'],
            ip_addr=sliced_df.at[m_i_adjust, 'ip address'],
            subnet=sliced_df.at[m_i_adjust, 'subnet'],
            gateway=sliced_df.at[m_i_adjust, 'default gateway']
        )
        self.nics.append(new_nic)


# ---------- Import Machine Data Functions ----------


def GShtOpen(client: str, gSheet: str, wrksheet: str) -> pygsheets.Worksheet:
    """
    Opens the specified google sheet.
    """
    sht = client.open(gSheet)
    wks = sht.worksheet_by_title(wrksheet)
    return wks


def NmFrmRow(df: pd.DataFrame, row: int) -> str:
    """
    pulls the machine name from a specified row in the dataframe
    Args:
        row (str): the string of a row pulled from google sheet dataframe.
        row_indx (str): the row number to pull name from
    """
    device_name = df.at[row, 'device name']
    return device_name


def NicNmFrmRow(df: pd.DataFrame, row: int) -> str:
    """
    pulls the nic name from a specified row in the dataframe
    Args:
        row (str): the string of a row pulled from google sheet dataframe.
        row_indx (str): the row number to pull name from
    """
    nic_name = df.at[row, 'name']
    return nic_name


def CalNicSlice(
        df: pd.DataFrame,
        nic_num: int,
        initial_num: int = 2,
        slc_size: int = 4,
        nic_cols: int = 6
        ) -> tuple:
    """
    calculates the slice of row needed for the appropriate NIC.
    Args:
        df (pd.DataFrame) the input dataframe
        nic_num (int) the current nic needing a slice
        initial_num (int) the initial offset for NIC 1
            defaults to 2 to skip 'device name' and 'location' columns
        slc_size (int) the size of the slices to make (the number of
            columns with NIC information). Default is 4 NIC columns [
            name, ip address, subnet, default gateway] = 4 items
    Returns:
        returns a tuple to make the slice from
    """
    if nic_num >= 1:
        start_slc = initial_num + (nic_cols * (nic_num))
        end_slc = start_slc + slc_size
    else:
        all_names_cols = df.columns.get_loc('name')
        first_name_col = np.argmax(all_names_cols)
        start_slc = first_name_col
        end_slc = nic_cols
    return start_slc, end_slc


def CalNumOfNics(df: pd.DataFrame, row: int) -> int:
    """
    Calculates the number of NICs on a row (ignores NICs with no names).
    Subtracts 1 from the row input to get the correct output row.
    Args:
        df (pd.DataFrame) the input dataframe
        row (int) the row number to calculate NIC number for.
    Returns: the number of NICs on a given row.
    """
    names_slices = df[['name']]
    nic_count = names_slices.apply(lambda row: (row != '').sum(), axis=1)
    row_index_fix = row - 1
    return nic_count[row_index_fix]


def CreateMachineInstances(
        df: pd.DataFrame,
        row_indx: int
        ) -> List[MachineInf]:
    machines = []
    for i in range(len(df)):
        machines.append(MachineInf(m_i=row_indx))
        row_indx += 1
    return machines


# ---------- Export to Powershell ----------

@dataclass
class PowershellExporter:
    """
    Class to handle the creation and management of PowerShell scripts
    for machine configuration.
    """
    machine: Type[MachineInf]
    rename_machines: bool = field(default_factory=bool)

    @staticmethod
    def subnet_mask_to_prefix_length(subnet_mask: str) -> int:
        """
        Converts a subnet mask into its corresponding prefix length.
        Args:
            subnet_mask (str): The subnet mask in string format
            (e.g., "255.255.255.0").
        Returns:
            int: The prefix length corresponding to the subnet mask.
        Raises:
            ValueError: If the subnet mask is invalid or not in the correct format.
        """
        # Check if the incoming string is in the correct subnet mask format
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', subnet_mask):
            raise ValueError(
                f"The subnet mask {subnet_mask} is not in the correct format.")
        # Split the subnet mask into octets and convert to binary
        octets = subnet_mask.split('.')
        binary_str = ''.join([format(int(octet), '08b') for octet in octets])
        # Validate each octet is within range and binary string is a valid mask
        for octet in octets:
            if not 0 <= int(octet) <= 255:
                raise ValueError(f"Invalid octet {octet} in subnet mask.")
        # Subnet masks must be contiguous ones followed by zeros
        if not re.match(r'^1*0*$', binary_str):
            raise ValueError(
                f"The subnet mask {subnet_mask} is not a valid subnet mask.")
        # Count the number of '1' bits which represents the prefix length
        prefix_length = binary_str.count('1')
        return prefix_length

    @staticmethod
    def dhcp_check(ip_address: str) -> bool:
        dhcp_bool = False
        if ip_address == 'dhcp':
            dhcp_bool = True
        else:
            dhcp_bool = False
        return (dhcp_bool)

    # def rename_machine(self, rename_switch: bool = False) -> bool:
    #     self.rename_machines = rename_switch

    @staticmethod
    def run_as_admin() -> str:
        """
        Text for the top of the script that checks if powershell running as admin and the relaunches as 
        admin if necessary.
        """
        command = [
            '''If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    # Relaunch the script with admin rights
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Exit
}'''
        ]
        return (command)

    def create_powershell_script(self):
        # PowerShell commands to set IP address and machine name
        machine = self.machine
        machine_name = machine.name
        nic_count = 0
        command_list = []
        nic_list = machine.nics
        command_list.append(self.run_as_admin())
        for nic in machine.nics:
            if_name = nic_list[nic_count].name
            subnet = nic_list[nic_count].subnet
            ip_addr = nic_list[nic_count].ip_addr
            gateway = nic_list[nic_count].gateway
            # ip_chkd_dhcp = self.dhcp_check(ip_addr)
            # logging.info(f'subnet = {subnet}')
            try:
                prefix = self.subnet_mask_to_prefix_length(subnet)
            except ValueError as e:
                print(f'{e} machine {machine_name} nic_count {nic_count}')
            if self.dhcp_check(ip_addr) is False:  # If no DHCP
                nic_commands = [
                    f'$interface = Get-NetAdapter -Name {if_name}',
                    f'$interface | New-NetIPAddress -IPAddress {ip_addr} -PrefixLength {prefix} -DefaultGateway {gateway}',  # Update IP address details as required
                    # f'Set-DnsClientServerAddress -InterfaceAlias "nic1" -ServerAddresses 192.168.1.1',  # Update DNS details as required
                    ]
            else:
                nic_commands = [
                    f'Set-NetIPInterface -InterfaceAlias {if_name} -Dhcp Enabled'
                    f'Set-DnsClientServerAddress -InterfaceAlias {if_name} -ResetServerAddress'
                ]
            command_list.append(nic_commands)
            nic_count += 1
        if self.rename_machines is False:
            pass
        else:
            machine_commands = [
                    f'Rename-Computer -NewName "{machine_name}"',  # Update machine name as required
                    'Restart-Computer -Force'  # This line will force a restart of the computer to apply changes
                    ]
            command_list.append(machine_commands)

        # Create and write the PowerShell script file
        script_path = f'outputs/{machine_name}_update_net_name.ps1'
        with open(script_path, 'w') as script_file:
            for command in command_list:
                for subcmd in command:
                    script_file.write(f'{subcmd}\n')
        logging.info(f'PowerShell script created: {script_path}')

# ---------- MAIN CODE BLOCK ----------


if __name__ == "__main__":
    # ---------- Import Machine Info ----------
    client = pygsheets.authorize(
        service_file=(
            'secret/credentials_python-int-2023-2e89fbfc8ab6.json'))
    wks = GShtOpen(
        client=client, gSheet='IP addresses py101', wrksheet='IP RESERVATIONS')

    # import worksheet as pandas dataframe
    mch_Df = wks.get_as_df(start='A2')  # the machines dataframe

    row_indx = 1  # the row index start number
    machinesList = CreateMachineInstances(mch_Df, row_indx)

    # add machine names to the list of machines
    for machine in machinesList:
        machine.name = NmFrmRow(mch_Df, machine.m_i-1)
        machine.num_of_nics = CalNumOfNics(mch_Df, machine.m_i)
        nic_num = 0
        for nic in range(machine.num_of_nics):
            slc = CalNicSlice(mch_Df, nic_num)
            machine.add_nic(mch_Df, slc)
            nic_num += 1
    # logging.info(f'machineList = {machinesList}')

    # ---------- Power Shell Export ----------
    # --- TRUE to set machine name and restart
    # --- FALSE = do not set machine name

    for machine in machinesList:
        rename_machines = False  # Toggles renaming and rebooting machines
        exporter = PowershellExporter(machine, rename_machines=rename_machines)
        exporter.create_powershell_script()

    # logging.info(f'debug machine list {machinesList[0].nics[1].name}')
    # logging.info(f'type = {type(machinesList[0].nics[1].name)}')
