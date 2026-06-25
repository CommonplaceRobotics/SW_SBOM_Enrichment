import argparse
import json
import hashlib
import os
from pathlib import Path

__version__ = "0.1.0"
__author__ = "MAB"


def HashFile(filename: str) -> str:
    """Hashes a file with SHA-512"""
    sha = hashlib.sha512()
    with open(filename, "rb") as f:
        while True:
            buf = f.read(4096)
            if not buf:
                break
            sha.update(buf)
    return sha.hexdigest()


class EnrichmentDataBaseComponent:
    """Describes a single component"""
    bom_ref = ""
    """
        ID of the component in the SBOM,
        this is matched with the start of the refs in the SBOM
    """
    purl = ""
    """PURL of the component"""
    creator = ""
    """Component e-mail address or website of the creator"""
    filenames = list()
    """Filename of the component"""
    filename_actual = ""
    """A confirmed file name"""
    deployable_hash = ""
    """SHA512 hash of the deployable component (executable or library)"""
    original_licenses = list()
    """Licenses assigned by the creator of the component"""
    distribution_licenses = list()
    """Licenses that can be used by a licensee"""
    effective_license = ""
    """License that is used by the creator of the SBOM"""
    is_executable: bool
    """Set true to set the executable property (see BSI TR)"""
    is_archive: bool
    """Set true to set the archive property (see BSI TR)"""
    is_structured: bool
    """Set true to set the structured property (see BSI TR)"""

    def ParseJSON(self, data: dict):
        if "bom-ref" in data:
            self.bom_ref = data["bom-ref"]
        if "purl" in data:
            self.purl = data["purl"]
        if len(self.bom_ref) == 0 and len(self.purl) == 0:
            print("Missing bom-ref and PURL in component definition")
            exit(-1)
        
        if "creator" in data:
            self.creator = data["creator"]
        if "filename" in data:
            if type(data["filename"]) is str:
                self.filenames = [data["filename"]]
            elif type(data["filename"]) is list:
                self.filenames = data["filename"]
        if "deployable_hash" in data:
            self.deployable_hash = data["deployable_hash"]
        if "original_licenses" in data:
            self.original_licenses = data["original_licenses"]
        if "distribution_licenses" in data:
            self.distribution_licenses = data["distribution_licenses"]
        if "effective_license" in data:
            self.effective_license = data["effective_license"]
        
        if "executable" in data:
            self.is_executable = str(data["executable"]).lower() == "true"
        if "archive" in data:
            self.is_archive = str(data["archive"]).lower() == "true"
        if "structured" in data:
            self.is_structured = str(data["structured"]).lower() == "true"

    def __str__(self) -> str:
        d = dict()
        d["bom-ref"] = self.bom_ref
        d["creator"] = self.creator
        d["filenames"] = self.filenames
        d["filename_actual"] = self.filename_actual
        d["deployable_hash"] = self.deployable_hash
        d["effective_license"] = self.effective_license
        try:
            d["is_executable"] = self.is_executable
        except AttributeError:
            pass
        try:
            d["is_archive"] = self.is_archive
        except AttributeError:
            pass
        try:
            d["is_structured"] = self.is_structured
        except AttributeError:
            pass
        return d.__str__()

    def GetDepFromNinja(self, dep_name: str, ninja_file: str) -> str:
        """
        Tries to get the file name for the given dependency from the build.ninja file.
        Parameters:
            dep_file: Name of the library to find without .a or .lib
            ninja_file: Path and name of the build.ninja file
        Returns:
            Filename (absolute or relative) or empty string
        """
        if Path(ninja_file).exists():
            with open(ninja_file) as f:
                for line in f:
                    if line.startswith("  LINK_LIBRARIES = "):
                        for entry in line.split():
                            filename = os.path.basename(entry)
                            if filename == dep_name or (filename == "lib" + dep_name + ".a") or (filename == "lib" + dep_name + ".so") or (filename == dep_name + ".lib") or (filename == dep_name + ".exe"):
                                return entry
        return ""

    def FindActualFileName(self):
        """Tries to find the actual file name"""
        if len(self.filename_actual) > 0:
            return
        
        # If not, check whether the ninja file exists and contains the given file
        ninja_file = cmake_build_dir + "/build.ninja"

        for dep_file in self.filenames:
            # Check whether the file exists
            if Path(dep_file).exists():
                self.filename_actual = dep_file
                break

            if Path(ninja_file).exists():
                file = self.GetDepFromNinja(dep_file, ninja_file)
                if len(file) > 0 and Path(file).exists():
                    self.filename_actual = file
                    break

    def CalculateHash(self, cmake_build_dir: str):
        """Calculates the if the file name is given"""
        if len(self.filenames) == 0:
            return
        
        self.FindActualFileName()

        if len(self.filename_actual) > 0:
            self.deployable_hash = HashFile(self.filename_actual)
        else:
            print("WARNING: Could not generate file hash for '" + self.bom_ref + "', file " + str(self.filenames) + " not found")


class EnrichtmentDataBase:
    """Describes the entries of the enrichment database"""
    components = list()
    """Enrichtment data for components"""
    remove_components = list()
    """List of components to remove"""

    def ReadFromFile(self, filename: str):
        print("Reading enrichment database from " + filename)
        with open(filename) as f:
            enrichment_json = json.load(f)
            if "components" in enrichment_json and type(enrichment_json) is dict:
                if type(enrichment_json["components"]) is list:
                    for component in enrichment_json["components"]:
                        edbCompo = EnrichmentDataBaseComponent()
                        edbCompo.ParseJSON(component)
                        
                        self.components.append(edbCompo)

                        # Debug printing the read data
                        print(edbCompo.__str__())

                if "remove-components" in enrichment_json and type(enrichment_json["remove-components"]) is list:
                    for component in enrichment_json["remove-components"]:
                        if type(component) is str and len(component) > 0:
                            self.remove_components.append(component)

    def CalculateHashes(self, cmake_build_dir: str):
        """Calculates the hashes for all given files"""
        for component in self.components:
            component.CalculateHash(cmake_build_dir)


def EnrichComponent(edb: EnrichtmentDataBase, component: dict):
    """
    Enriches a SBOM component
    Parameters:
        edb: Enrichment data base
        component: SBOM component object
    """
    for enrich_component in edb.components:
        bom_ref = component["bom-ref"]
        if len(enrich_component.bom_ref) == 0:
            continue

        if bom_ref.startswith(enrich_component.bom_ref):
            # Create structure
            if "properties" not in component:
                component["properties"] = list()
            if "externalReferences" not in component:
                component["externalReferences"] = list()
            if "licenses" not in component:
                component["licenses"] = list()

            # Creator
            if len(enrich_component.creator) > 0:
                print("Adding manufacturer contact to '" + enrich_component.bom_ref + "'...")
                if "manufacturer" not in component:
                    component["manufacturer"] = dict()
                if "@" in enrich_component.creator:
                    if "contact" not in component["manufacturer"]:
                        component["manufacturer"]["contact"] = list()
                    component["manufacturer"]["contact"].append({"email" : enrich_component.creator})
                else:
                    component["manufacturer"]["url"] = [ enrich_component.creator ]

                # sbomqs reads the manufacturer info from "supplier" instead of "manufacturer"
                print("Adding supplier contact to '" + enrich_component.bom_ref + "'...")
                if "supplier" not in component:
                    component["supplier"] = dict()
                if "@" in enrich_component.creator:
                    if "contact" not in component["supplier"]:
                        component["supplier"]["contact"] = list()
                    component["supplier"]["contact"].append({"email" : enrich_component.creator})
                else:
                    component["supplier"]["url"] = [ enrich_component.creator ]
            
            # Original Licenses
            for license in enrich_component.distribution_licenses:
                component["licenses"].append({"license": {"id": license, "acknowledgement": "declared"}})
                # Remove standard licenses in "name" property
                for li in component["licenses"]:
                    if "name" in li and li["name"] == license:
                        component["licenses"].remove(li)

            # Distribution Licenses
            for license in enrich_component.distribution_licenses:
                component["licenses"].append({"license": {"id": license, "acknowledgement": "concluded"}})
                # Remove standard licenses in "name" property
                for li in component["licenses"]:
                    if "name" in li and li["name"] == license:
                        component["licenses"].remove(li)
                
            # Effective License
            if len(enrich_component.effective_license) > 0:
                has_effective_license = False
                for p in component["properties"]:
                    if "name" in p and p["name"] == "bsi:component:effectiveLicense":
                        has_effective_license = True
                if not has_effective_license:
                    print("Adding effective license to '" + enrich_component.bom_ref + "'...")
                    licenseData = {"name": "bsi:component:effectiveLicense", "value": enrich_component.effective_license}
                    component["properties"].append(licenseData)
            
            # Filename of the component
            if len(enrich_component.filename_actual) > 0:
                filename = os.path.basename(enrich_component.filename_actual)
                has_filename = False
                for p in component["properties"]:
                    if "name" in p and p["name"] == "bsi:component:filename":
                        has_filename = True
                if not has_filename:
                    print("Adding filename '" + enrich_component.filename_actual + "' to '" + enrich_component.bom_ref + "'...")
                    filenameData = {"name": "bsi:component:filename", "value": filename}
                    component["properties"].append(filenameData)

            # Hash value of the deployable component
            if len(enrich_component.deployable_hash) > 0 and len(enrich_component.filename_actual) > 0:
                print("Adding deployable hash of file '" + enrich_component.filename_actual + "' to '" + enrich_component.bom_ref + "'...")
                uri = "file://" + enrich_component.filename_actual
                hashData = {"url": uri, "type": "distribution", "hashes": [{"alg": "SHA-512", "content": enrich_component.deployable_hash}]}
                component["externalReferences"].append(hashData)

            # Set executable property
            try:
                print("Setting '" + enrich_component.bom_ref + "' executable property...")
                if enrich_component.is_executable is True:
                    component["properties"].append({"name": "bsi:component:executable", "value": "executable"})
                else:
                    component["properties"].append({"name": "bsi:component:executable", "value": "non-executable"})
            except AttributeError:
                pass

            # Set archive property
            try:
                print("Setting '" + enrich_component.bom_ref + "' archive property...")
                if enrich_component.is_archive is True:
                    component["properties"].append({"name": "bsi:component:archive", "value": "archive"})
                else:
                    component["properties"].append({"name": "bsi:component:archive", "value": "no archive"})
            except AttributeError:
                pass

            # Set structured property
            try:
                print("Setting '" + enrich_component.bom_ref + "' structured property...")
                if enrich_component.is_structured is True:
                    component["properties"].append({"name": "bsi:component:structured", "value": "structured"})
                else:
                    component["properties"].append({"name": "bsi:component:structured", "value": "unstructured"})
            except AttributeError:
                pass

            # print(component)
            break

def FindBomRefsForPURL(edb: EnrichtmentDataBase, sbom_json: dict):
    """Gets the bom-refs via the PURL if the bom-ref is not defined in the enrichment file"""
    for edbcomp in edb.components:
        if len(edbcomp.bom_ref) == 0:
            for component in sbom_json["components"]:
                if "bom-ref" in component and "purl" in component and component["purl"].startswith(edbcomp.purl):
                    edbcomp.bom_ref = component["bom-ref"]
                    print("Found bom-ref '" + edbcomp.bom_ref + "' for purl '" + edbcomp.purl + "'")
                    break

        if len(edbcomp.bom_ref) == 0:
            if "metadata" in sbom_json and "component" in sbom_json["metadata"]:
                component = sbom_json["metadata"]["component"]
                if "bom-ref" in component and "purl" in component and component["purl"].startswith(edbcomp.purl):
                    edbcomp.bom_ref = component["bom-ref"]
                    print("Found bom-ref '" + edbcomp.bom_ref + "' for purl '" + edbcomp.purl + "'")


cmake_build_dir = ""
"""Name of the CMake build directory, may be empty"""
enrichment_file = ""
"""The enrichment data file, must be in JSON format"""
sbom_file_in = ""
"""The SBOM input file, must be in CycloneDX JSON format"""
sbom_file_out = ""
"""The SBOM output file, must be in CycloneDX JSON format"""

argparser = argparse.ArgumentParser(description='Commonplace Robotics GmbH SBOM enrichment tool v' + __version__)
argparser.add_argument("enrichtment_file", type=str, help='Enrichment data file')
argparser.add_argument("sbom_in", type=str, help='SBOM input file')
argparser.add_argument("-o", "--out", type=str, help='SBOM output file')
argparser.add_argument("-b", "--cmake_dir", type=str, help='CMake build directory')
args = argparser.parse_args()

print('Commonplace Robotics GmbH SBOM enrichment tool v' + __version__)

if type(args.enrichtment_file) is str:
    enrichment_file = args.enrichtment_file
if type(args.sbom_in) is str:
    sbom_file_in = sbom_file_out = args.sbom_in
if type(args.out) is str:
    sbom_file_out = args.out
if type(args.cmake_dir) is str:
    cmake_build_dir = args.cmake_dir

if len(cmake_build_dir) > 0 and not Path(cmake_build_dir).exists():
    print("Error: CMake build directory given but it does not exist")
    exit(-1)

if len(enrichment_file) == 0:
    print("Error: Enrichment file not given")
    exit(-1)

if len(sbom_file_in) == 0:
    print("Error: SBOM input file not given")
    exit(-1)

if len(sbom_file_out) == 0:
    print("Error: SBOM output file not given")
    exit(-1)

if not Path(enrichment_file).exists():
    print("Error: Enrichment file '" + enrichment_file + "' does not exist")
    exit(-1)

if not Path(sbom_file_in).exists():
    print("Error: SBOM input file '" + sbom_file_in + "' does not exist")
    exit(-1)

# Read enrichment file
edb = EnrichtmentDataBase()
edb.ReadFromFile(enrichment_file)

# Read SBOM
print("Reading SBOM from " + sbom_file_in)
with open(sbom_file_in) as f:
    sbom_json = json.load(f)

# Get bom-refs from PURL
FindBomRefsForPURL(edb, sbom_json)

edb.CalculateHashes(cmake_build_dir)

# Remove components
for rem_component in edb.remove_components:
    bom_ref = ""

    for component in sbom_json["components"]:
        if component["bom-ref"].startswith(rem_component):
            # Get bom-ref from components list
            bom_ref = component["bom-ref"]

            # Remove from components list
            print("Removing component '" + bom_ref + "'...")
            sbom_json["components"].remove(component)

    if len(bom_ref) > 0:
        for dep in sbom_json["dependencies"]:
            # Remove own dependencies entry
            if dep["ref"] == bom_ref:
                print("Removing dependencies of '" + bom_ref + "'...")
                sbom_json["dependencies"].remove(dep)

        for dep in sbom_json["dependencies"]:
            # Remove from dependencies of other components
            if "dependsOn" in dep and bom_ref in dep["dependsOn"]:
                print("Removing dependency to '" + bom_ref + "' from '" + dep["ref"] + "'...")
                dep["dependsOn"].remove(bom_ref)

# Enrich components
for component in sbom_json["components"]:
    EnrichComponent(edb, component)

# Enrich target component
if "metadata" in sbom_json and "component" in sbom_json["metadata"]:
    component = sbom_json["metadata"]["component"]
    EnrichComponent(edb, component)

print("Writing SBOM to " + sbom_file_out)
with open(sbom_file_out, "w") as f:
    f.write(json.dumps(sbom_json, indent=2))
