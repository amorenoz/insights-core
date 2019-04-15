# from insights.parsers.virt_what import VirtWhat as VWP
# from insights.combiners.virt_what import VirtWhat
from insights.combiners.cloud_provider import CloudProvider
from insights.parsers.installed_rpms import InstalledRpms as IRPMS
from insights.parsers.dmidecode import DMIDecode
from insights.parsers.yum import YumRepoList
from insights.tests import context_wrap

RPMS = """
gnome-terminal-3.28.2-2.fc28.x86_64
python3-IPy-0.81-21.fc28.noarch
gnu-free-serif-fonts-20120503-17.fc28.noarch
""".strip()

RPMS_AWS = """
gnome-terminal-3.28.2-2.fc28.x86_64
python3-IPy-0.81-21.fc28.noarch
gnu-free-serif-fonts-20120503-17.fc28.noarch
rh-amazon-rhui-client-2.2.124-1.el7
""".strip()

RPMS_GOOGLE = """
gnome-terminal-3.28.2-2.fc28.x86_64
python3-IPy-0.81-21.fc28.noarch
gnu-free-serif-fonts-20120503-17.fc28.noarch
google-rhui-client-5.1.100-1.el7
""".strip()

RPMS_AZURE = """
gnome-terminal-3.28.2-2.fc28.x86_64
python3-IPy-0.81-21.fc28.noarch
gnu-free-serif-fonts-20120503-17.fc28.noarch
WALinuxAgent-2.2.18-1.el7
""".strip()

YUM_REPOLIST_AZURE = """
Loaded plugins: enabled_repos_upload, package_upload, product-id, search-
              : disabled-repos, security, subscription-manager
repo id                                repo name                          status
rhel-6-server-rpms                     Red Hat Enterprise Linux 6 Server  20584
rhel-6-server-satellite-tools-6.3-rpms Red Hat Satellite Tools 6.3 (for R    40
rhui-microsoft-azure-rhel7-2.2-74      Red Hat Software Collect             600
repolist: 21224
Uploading Enabled Repositories Report
Loaded plugins: product-id, subscription-manager
""".strip()

YUM_REPOLIST_NOT_AZURE = """
Loaded plugins: enabled_repos_upload, package_upload, product-id, search-
              : disabled-repos, security, subscription-manager
repo id                                repo name                          status
rhel-6-server-rpms                     Red Hat Enterprise Linux 6 Server  20584
rhel-6-server-satellite-tools-6.3-rpms Red Hat Satellite Tools 6.3 (for R    40
repolist: 21224
Uploading Enabled Repositories Report
Loaded plugins: product-id, subscription-manager
""".strip()


DMIDECODE = '''
# dmidecode 2.11
SMBIOS 2.7 present.
188 structures occupying 5463 bytes.
Table at 0xBFFCB000.

Handle 0x0000, DMI type 0, 24 bytes
BIOS Information
\tVendor: HP
\tVersion: P70
\tRelease Date: 03/01/2013
\tAddress: 0xF0000
\tRuntime Size: 64 kB
\tROM Size: 8192 kB
\tCharacteristics:
\t\tPCI is supported
\t\tPNP is supported
\t\tBIOS is upgradeable
\t\tBIOS shadowing is allowed
\t\tESCD support is available
\t\tBoot from CD is supported
\t\tSelectable boot is supported
\t\tEDD is supported
\t\t5.25"/360 kB floppy services are supported (int 13h)
\t\t5.25"/1.2 MB floppy services are supported (int 13h)
\t\t3.5"/720 kB floppy services are supported (int 13h)
\t\tPrint screen service is supported (int 5h)
\t\tj042 keyboard services are supported (int 9h)
\t\tSerial services are supported (int 14h)
\t\tPrinter services are supported (int 17h)
\t\tCGA/mono video services are supported (int 10h)
\t\tACPI is supported
\t\tUSB legacy is supported
\t\tBIOS boot specification is supported
\t\tFunction key-initiated network boot is supported
\t\tTargeted content distribution is supported
\tFirmware Revision: 1.22

Handle 0x0100, DMI type 1, 27 bytes
System Information
\tManufacturer: HP
\tProduct Name: ProLiant DL380p Gen8
\tVersion: Not Specified
\tSerial Number: 2M23360006
\tUUID: 34373936-3439-4D32-3233-333630303036
\tWake-up Type: Power Switch
\tSKU Number: 697494-S01
\tFamily: ProLiant

Handle 0x0300, DMI type 3, 21 bytes
chassis information
\tmanufacturer: hp
\ttype: rack mount chassis
\tlock: not present
\tversion: not specified
\tserial number: 2m23360006
\tasset Tag:
\tBoot-up State: Safe
\tPower Supply State: Safe
\tThermal State: Safe
\tSecurity Status: Unknown
\tOEM Information: 0x00000000
\tHeight: 2 U
\tNumber Of Power Cords: 2
\tContained Elements: 0

Handle 0x0401, DMI type 4, 32 bytes
Processor Information
\tSocket Designation: CPU 1
\tType: Central Processor
\tFamily: Other
\tManufacturer: Bochs
\tID: A1 06 02 00 FD FB 8B 17
\tVersion: Not Specified
\tVoltage: Unknown
\tExternal Clock: Unknown
\tMax Speed: 2000 MHz
\tCurrent Speed: 2000 MHz
\tStatus: Populated, Enabled
\tUpgrade: Other
\tL1 Cache Handle: Not Provided
\tL2 Cache Handle: Not Provided
\tL3 Cache Handle: Not Provided

Handle 0x0402, DMI type 4, 32 bytes
Processor Information
\tSocket Designation: CPU 2
\tType: Central Processor
\tFamily: Other
\tManufacturer: Bochs
\tID: A1 06 02 00 FD FB 8B 17
\tVersion: Not Specified
\tVoltage: Unknown
\tExternal Clock: Unknown
\tMax Speed: 2000 MHz
\tCurrent Speed: 2000 MHz
\tStatus: Populated, Enabled
\tUpgrade: Other
\tL1 Cache Handle: Not Provided
\tL2 Cache Handle: Not Provided
\tL3 Cache Handle: Not Provided

Handle 0x0037, DMI type 127, 4 bytes.
End Of Table
'''

DMIDECODE_AWS = '''
# dmidecode 2.12-dmifs
SMBIOS 2.4 present.
11 structures occupying 310 bytes.
Table at 0x000EB01F.

Handle 0x0000, DMI type 0, 24 bytes
BIOS Information
\tVendor: Xen
\tVersion: 4.2.amazon
\tRelease Date: 12/09/2016
\tAddress: 0xE8000
\tRuntime Size: 96 kB
\tROM Size: 64 kB
\tCharacteristics:
\t\tPCI is supported
\t\tEDD is supported
\t\tTargeted content distribution is supported
\tBIOS Revision: 4.2

Handle 0x0100, DMI type 1, 27 bytes
System Information
\tManufacturer: Xen
\tProduct Name: HVM domU
\tVersion: 4.2.amazon
\tSerial Number: ec2f58af-2dad-c57e-88c0-a81cb6084290
\tUUID: EC2F58AF-2DAD-C57E-88C0-A81CB6084290
\tWake-up Type: Power Switch
\tSKU Number: Not Specified
\tFamily: Not Specified

Handle 0x0300, DMI type 3, 13 bytes
Chassis Information
\tManufacturer: Xen
\tType: Other
\tLock: Not Present
\tVersion: Not Specified
\tSerial Number: Not Specified
\tAsset Tag: Not Specified
\tBoot-up State: Safe
\tPower Supply State: Safe
\tThermal State: Safe
\tSecurity Status: Unknown
'''

DMIDECODE_AWS_UUID = '''
# dmidecode 2.12-dmifs
SMBIOS 2.4 present.
11 structures occupying 310 bytes.
Table at 0x000EB01F.

Handle 0x0000, DMI type 0, 24 bytes
BIOS Information
\tVendor: Xen
\tVersion: 4.2
\tRelease Date: 12/09/2016
\tAddress: 0xE8000
\tRuntime Size: 96 kB
\tROM Size: 64 kB
\tCharacteristics:
\t\tPCI is supported
\t\tEDD is supported
\t\tTargeted content distribution is supported
\tBIOS Revision: 4.2

Handle 0x0100, DMI type 1, 27 bytes
System Information
\tManufacturer: Xen
\tProduct Name: HVM domU
\tVersion: 4.2.amazon
\tSerial Number: ec2f58af-2dad-c57e-88c0-a81cb6084290
\tUUID: EC2F58AF-2DAD-C57E-88C0-A81CB6084290
\tWake-up Type: Power Switch
\tSKU Number: Not Specified
\tFamily: Not Specified

Handle 0x0300, DMI type 3, 13 bytes
Chassis Information
\tManufacturer: Xen
\tType: Other
\tLock: Not Present
\tVersion: Not Specified
\tSerial Number: Not Specified
\tAsset Tag: Not Specified
\tBoot-up State: Safe
\tPower Supply State: Safe
\tThermal State: Safe
\tSecurity Status: Unknown
'''

DMIDECODE_GOOGLE = '''
# dmidecode 2.12-dmifs
SMBIOS 2.4 present.
11 structures occupying 310 bytes.
Table at 0x000EB01F.

Handle 0x0000, DMI type 0, 24 bytes
BIOS Information
\tVendor: Google
\tVersion: Google
\tRelease Date: 12/09/2016
\tAddress: 0xE8000
\tRuntime Size: 96 kB
\tROM Size: 64 kB
\tCharacteristics:
\t\tPCI is supported
\t\tEDD is supported
\t\tTargeted content distribution is supported
\tBIOS Revision: 4.2

Handle 0x0100, DMI type 1, 27 bytes
System Information
\tManufacturer: Xen
\tProduct Name: HVM domU
\tVersion: 4.2.amazon
\tSerial Number: ec2f58af-2dad-c57e-88c0-a81cb6084290
\tUUID: EC2F58AF-2DAD-C57E-88C0-A81CB6084290
\tWake-up Type: Power Switch
\tSKU Number: Not Specified
\tFamily: Not Specified

Handle 0x0300, DMI type 3, 13 bytes
Chassis Information
\tManufacturer: Xen
\tType: Other
\tLock: Not Present
\tVersion: Not Specified
\tSerial Number: Not Specified
\tAsset Tag: Not Specified
\tBoot-up State: Safe
\tPower Supply State: Safe
\tThermal State: Safe
\tSecurity Status: Unknown
'''

DMIDECODE_AZURE_ASSET_TAG = """
# dmidecode 3.1
Getting SMBIOS data from sysfs.
SMBIOS 2.8 present.
10 structures occupying 511 bytes.
Table at 0x000F6050.

Handle 0x0000, DMI type 0, 24 bytes
BIOS Information
\tVendor: SeaBIOS
\tVersion: 1.11.0-2.el7
\tRelease Date: 04/01/2014
\tAddress: 0xE8000
\tRuntime Size: 96 kB
\tROM Size: 64 kB
\tCharacteristics:
\t\tBIOS characteristics not supported
\t\tTargeted content distribution is supported
\tBIOS Revision: 0.0

Handle 0x0100, DMI type 1, 27 bytes
System Information
\tManufacturer: oVirt
\tProduct Name: oVirt Node
\tVersion: 7-5.1804.4.el7.centos
\tSerial Number: 30393137-3436-584D-5136-323830304E46
\tUUID: a35ae32b-ed0a-49a4-9dbb-eecf21f88aab
\tWake-up Type: Power Switch
\tSKU Number: Not Specified
\tFamily: Red Hat Enterprise Linux

Handle 0x0300, DMI type 3, 21 bytes
Chassis Information
\tManufacturer: Red Hat
\tType: Other
\tLock: Not Present
\tVersion: RHEL 7.2.0 PC (i440FX + PIIX, 1996)
\tSerial Number: Not Specified
\tAsset Tag: 7783-7084-3265-9085-8269-3286-77
\tBoot-up State: Safe
\tPower Supply State: Safe
\tThermal State: Safe
\tSecurity Status: Unknown
\tOEM Information: 0x00000000
\tHeight: Unspecified
\tNumber Of Power Cords: Unspecified
\tContained Elements: 0
"""

DMIDECODE_FAIL = "# dmidecode 2.11\n# No SMBIOS nor DMI entry point found, sorry.\n"


def test_rpm_google():
    irpms = IRPMS(context_wrap(RPMS_GOOGLE))
    dmi = DMIDecode(context_wrap(DMIDECODE))
    yrl = YumRepoList(context_wrap(YUM_REPOLIST_NOT_AZURE))
    ret = CloudProvider(irpms, dmi, yrl)
    assert ret.cloud_provider == 'google'
    assert ret.cp_rpms.get('google')[0] == 'google-rhui-client-5.1.100-1.el7'


def test_rpm_aws():
    irpms = IRPMS(context_wrap(RPMS_AWS))
    dmi = DMIDecode(context_wrap(DMIDECODE))
    yrl = YumRepoList(context_wrap(YUM_REPOLIST_NOT_AZURE))
    ret = CloudProvider(irpms, dmi, yrl)
    assert ret.cloud_provider == 'aws'
    assert ret.cp_rpms.get('aws')[0] == 'rh-amazon-rhui-client-2.2.124-1.el7'


def test_rpm_azure():
    irpms = IRPMS(context_wrap(RPMS_AZURE))
    dmi = DMIDecode(context_wrap(DMIDECODE))
    yrl = YumRepoList(context_wrap(YUM_REPOLIST_NOT_AZURE))
    ret = CloudProvider(irpms, dmi, yrl)
    assert ret.cloud_provider == 'azure'
    assert ret.cp_rpms.get('azure')[0] == 'WALinuxAgent-2.2.18-1.el7'


def test__yum_azure():
    irpms = IRPMS(context_wrap(RPMS))
    dmi = DMIDecode(context_wrap(DMIDECODE))
    yrl = YumRepoList(context_wrap(YUM_REPOLIST_AZURE))
    ret = CloudProvider(irpms, dmi, yrl)
    assert ret.cloud_provider == 'azure'
    assert 'rhui-microsoft-azure-rhel7-2.2-74' in ret.cp_yum.get('azure')


def test__bios_version_aws():
    irpms = IRPMS(context_wrap(RPMS))
    dmi = DMIDecode(context_wrap(DMIDECODE_AWS))
    yrl = YumRepoList(context_wrap(YUM_REPOLIST_AZURE))
    ret = CloudProvider(irpms, dmi, yrl)
    assert ret.cloud_provider == 'aws'
    assert ret.cp_bios_version['aws'] == '4.2.amazon'


def test__bios_vendor_google():
    irpms = IRPMS(context_wrap(RPMS))
    dmi = DMIDecode(context_wrap(DMIDECODE_GOOGLE))
    yrl = YumRepoList(context_wrap(YUM_REPOLIST_AZURE))
    ret = CloudProvider(irpms, dmi, yrl)
    assert ret.cloud_provider == 'google'
    assert ret.cp_bios_vendor['google'] == 'Google'


def test__asset_tag_azure():
    irpms = IRPMS(context_wrap(RPMS))
    dmi = DMIDecode(context_wrap(DMIDECODE_AZURE_ASSET_TAG))
    yrl = YumRepoList(context_wrap(YUM_REPOLIST_NOT_AZURE))
    ret = CloudProvider(irpms, dmi, yrl)
    assert ret.cloud_provider == 'azure'
    assert ret.cp_asset_tag['azure'] == '7783-7084-3265-9085-8269-3286-77'


def test__uuid():
    irpms = IRPMS(context_wrap(RPMS))
    dmi = DMIDecode(context_wrap(DMIDECODE_AWS_UUID))
    yrl = YumRepoList(context_wrap(YUM_REPOLIST_NOT_AZURE))
    ret = CloudProvider(irpms, dmi, yrl)
    assert ret.cloud_provider == 'aws'
    assert ret.cp_uuid['aws'] == 'EC2F58AF-2DAD-C57E-88C0-A81CB6084290'
