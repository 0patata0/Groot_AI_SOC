#!/usr/bin/env python3
"""Rebuild this lab using an existing Boot JAR, without downloading dependencies.

inspect BASE.jar NEW_DIRECTORY extracts verified libraries to NEW_DIRECTORY/lib.
package BASE.jar COMPILED_CLASSES RESOURCES NEW.jar replaces application content.
Compilation is deliberately separate and must use the existing server's JDK 8.
Both commands print JSON; every dependency SHA-256 is included in the report.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import zipfile


MAX_ARCHIVE = 128 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
START_CLASS = "fr.christophetd.log4shell.vulnerableapp.VulnerableAppApplication"
CLASSES = "BOOT-INF/classes/"
LIB = "BOOT-INF/lib/"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def checked_archive(data):
    if not 0 < len(data) <= MAX_ARCHIVE:
        raise ValueError("archive size outside allowed bounds")
    archive = zipfile.ZipFile(io.BytesIO(data))
    entries = archive.infolist()
    names = [entry.filename for entry in entries]
    if len(entries) > 20000 or len(set(names)) != len(names):
        archive.close()
        raise ValueError("duplicate or excessive ZIP entries")
    if sum(entry.file_size for entry in entries) > MAX_EXPANDED:
        archive.close()
        raise ValueError("expanded archive exceeds size limit")
    for entry in entries:
        parts = entry.filename.rstrip("/").split("/")
        kind = stat.S_IFMT(entry.external_attr >> 16)
        if (not all(parts) or any(part in (".", "..") for part in parts)
                or "\\" in entry.filename or ":" in entry.filename
                or "\x00" in entry.filename or entry.flag_bits & 1
                or kind not in (0, stat.S_IFREG, stat.S_IFDIR)):
            archive.close()
            raise ValueError("unsafe ZIP entry: " + entry.filename)
    return archive


def manifest_fields(data):
    text = data.decode("utf-8").replace("\r\n", "\n").replace("\n ", "")
    fields = {}
    # Only the main section defines the application entry point.
    for line in text.split("\n\n", 1)[0].splitlines():
        if not line:
            continue
        if ": " not in line:
            raise ValueError("malformed JAR manifest")
        key, value = line.split(": ", 1)
        if key in fields:
            raise ValueError("duplicate manifest field")
        fields[key] = value
    return fields


def reject_symlink_components(path):
    path = Path(os.path.abspath(path))
    for part in (path,) + tuple(path.parents):
        if part.is_symlink():
            raise ValueError("symlink paths are not accepted: " + str(part))
    return path


def regular_bytes(path):
    path = reject_symlink_components(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_ARCHIVE:
        raise ValueError("expected a nonempty regular file: " + str(path))
    return path.read_bytes()


def verify_library(data, artifact, version, group=None, required_class=None):
    with checked_archive(data) as library:
        if group is not None:
            properties = library.read("META-INF/maven/" + group + "/" + artifact + "/pom.properties")
            fields = {}
            for line in properties.decode("utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith(("#", "!")) and "=" in line:
                    key, value = line.split("=", 1)
                    if key.strip() in fields:
                        raise ValueError("duplicate Maven property")
                    fields[key.strip()] = value.strip()
            expected = {"groupId": group, "artifactId": artifact, "version": version}
            if any(fields.get(key) != value for key, value in expected.items()):
                raise ValueError("Maven metadata mismatch for " + artifact)
        else:
            fields = manifest_fields(library.read("META-INF/MANIFEST.MF"))
            if fields.get("Implementation-Version") != version:
                raise ValueError("manifest version mismatch for " + artifact)
        if required_class and not library.read(required_class):
            raise ValueError("missing library class: " + required_class)


def inspect_base(data):
    with checked_archive(data) as archive:
        names = archive.namelist()
        for name in names:
            upper = name.upper()
            if upper.startswith("META-INF/") and "/" not in upper[9:] and (
                    upper.endswith((".SF", ".RSA", ".DSA", ".EC"))
                    or upper[9:].startswith("SIG-")):
                raise ValueError("signed outer JAR cannot be repackaged")
        fields = manifest_fields(archive.read("META-INF/MANIFEST.MF"))
        expected = {
            "Main-Class": "org.springframework.boot.loader.JarLauncher",
            "Start-Class": START_CLASS,
            "Spring-Boot-Version": "2.6.1",
        }
        if any(fields.get(key) != value for key, value in expected.items()):
            raise ValueError("base JAR Spring Boot entry point/version mismatch")
        if not archive.read("org/springframework/boot/loader/JarLauncher.class"):
            raise ValueError("missing Spring Boot loader")
        libraries = {}
        for entry in archive.infolist():
            if entry.filename.startswith(LIB) and not entry.is_dir():
                relative = entry.filename[len(LIB):]
                if "/" in relative or not relative.endswith(".jar"):
                    raise ValueError("unexpected nested library path")
                if entry.compress_type != zipfile.ZIP_STORED:
                    raise ValueError("Spring Boot nested libraries must use ZIP_STORED")
                libraries[entry.filename] = archive.read(entry)
        required = (
            ("spring-boot", "2.6.1", None, "org/springframework/boot/SpringApplication.class"),
            ("spring-boot-autoconfigure", "2.6.1", None, None),
            ("log4j-api", "2.14.1", "org.apache.logging.log4j", "org/apache/logging/log4j/LogManager.class"),
            ("log4j-core", "2.14.1", "org.apache.logging.log4j", "org/apache/logging/log4j/core/lookup/JndiLookup.class"),
            ("log4j-slf4j-impl", "2.14.1", "org.apache.logging.log4j", "org/slf4j/impl/StaticLoggerBinder.class"),
        )
        for artifact, version, group, required_class in required:
            selected = sorted(name for name in libraries if re.fullmatch(
                re.escape(LIB + artifact) + r"-\d[^/]*\.jar", name))
            expected_name = LIB + artifact + "-" + version + ".jar"
            if selected != [expected_name]:
                raise ValueError("dependency version/set mismatch: " + artifact)
            verify_library(libraries[expected_name], artifact, version, group, required_class)
        unindexed_libraries = []
        if "BOOT-INF/classpath.idx" in names:
            indexed = []
            for line in archive.read("BOOT-INF/classpath.idx").decode("utf-8").splitlines():
                match = re.fullmatch(r'- "(BOOT-INF/lib/[^"\r\n]+\.jar)"', line)
                if not match:
                    raise ValueError("unrecognized classpath.idx format")
                indexed.append(match.group(1))
            unindexed_libraries = sorted(set(libraries) - set(indexed))
            # Boot 2.6.1 may append its layer extraction tool after generating
            # the application classpath index. Permit only that exact optional
            # tool, whose version and contents are checked independently.
            layer_tool = LIB + "spring-boot-jarmode-layertools-2.6.1.jar"
            if (len(indexed) != len(set(indexed)) or set(indexed) - set(libraries)
                    or set(unindexed_libraries) - {layer_tool}):
                raise ValueError("classpath.idx does not match the dependency set")
            if unindexed_libraries:
                verify_library(libraries[layer_tool], "spring-boot-jarmode-layertools", "2.6.1",
                               required_class="org/springframework/boot/jarmode/layertools/LayerToolsJarMode.class")
        if "BOOT-INF/layers.idx" in names:
            layers = archive.read("BOOT-INF/layers.idx").decode("utf-8")
            # A folder-level entry still covers the new application. Individual
            # old class/resource entries would become stale after replacement.
            references = re.findall(r'"(BOOT-INF/classes/[^"\r\n]*)"', layers)
            if references != [CLASSES]:
                raise ValueError("layers.idx must contain one whole application directory entry")
        # Read every entry now to validate CRCs before producing any output.
        for entry in archive.infolist():
            archive.read(entry)
        report = {
            "base_sha256": sha256(data),
            "spring_boot": "2.6.1",
            "log4j": "2.14.1",
            "libraries_sha256": {name: sha256(content) for name, content in sorted(libraries.items())},
            "classpath_idx": "preserved" if "BOOT-INF/classpath.idx" in names else "absent",
            "unindexed_libraries": unindexed_libraries,
            "layers_idx": "preserved" if "BOOT-INF/layers.idx" in names else "absent",
        }
    return libraries, report


def extract_libraries(base, destination):
    libraries, report = inspect_base(regular_bytes(base))
    destination = reject_symlink_components(destination)
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    try:
        lib_dir = destination / "lib"
        lib_dir.mkdir(mode=0o700)
        for name, data in sorted(libraries.items()):
            with (lib_dir / name[len(LIB):]).open("xb") as output:
                output.write(data)
    except BaseException:
        # Only this command's newly created directory is eligible for cleanup.
        shutil.rmtree(destination)
        raise
    report["library_directory"] = str(lib_dir)
    return report


def application_files(directory, classes=False):
    directory = reject_symlink_components(directory)
    if not directory.is_dir():
        raise ValueError("application input must be a directory")
    result = {}
    for root, dirs, files in os.walk(directory, followlinks=False):
        for name in dirs + files:
            path = Path(root) / name
            info = path.lstat()
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ValueError("application tree contains a symlink or special file")
        for name in sorted(files):
            path = Path(root) / name
            relative = path.relative_to(directory).as_posix()
            if any(character in relative for character in ("\\", ":", "\x00")):
                raise ValueError("unsafe application filename")
            if path.stat().st_size > MAX_ARCHIVE:
                raise ValueError("application file exceeds size limit")
            data = path.read_bytes()
            if classes:
                if not relative.endswith(".class") or data[:4] != b"\xca\xfe\xba\xbe" or len(data) < 8:
                    raise ValueError("compiled classes directory must contain only Java class files")
                if int.from_bytes(data[6:8], "big") > 52:
                    raise ValueError("application class requires Java newer than Java 8")
            result[CLASSES + relative] = data
    if sum(map(len, result.values())) > MAX_EXPANDED:
        raise ValueError("application content exceeds size limit")
    return result


def package_application(base, compiled_classes, resources, destination):
    base_data = regular_bytes(base)
    libraries, report = inspect_base(base_data)
    content = application_files(compiled_classes, classes=True)
    resource_content = application_files(resources)
    if content.keys() & resource_content.keys() or any(name.endswith(".class") for name in resource_content):
        raise ValueError("resources must not replace compiled classes")
    content.update(resource_content)
    for name in (
            START_CLASS.replace(".", "/") + ".class",
            "fr/christophetd/log4shell/vulnerableapp/MainController.class",
            "application.properties", "log4j2-spring.xml", "static/index.html",
            "static/app.js", "static/app.css"):
        if not content.get(CLASSES + name):
            raise ValueError("required application file missing: " + name)
    destination = reject_symlink_components(destination)
    # Exclusive creation prevents overwriting the original or any existing file.
    with destination.open("xb") as output:
        try:
            with checked_archive(base_data) as original, zipfile.ZipFile(output, "w") as packaged:
                packaged.comment = original.comment
                for entry in original.infolist():
                    if not entry.filename.startswith(CLASSES):
                        packaged.writestr(entry, original.read(entry))
                # ClassLoader resource/package discovery requires directory
                # entries as well as class files, including classpath:/static/.
                directories = {CLASSES}
                for name in content:
                    parts = name[len(CLASSES):].split("/")[:-1]
                    for depth in range(1, len(parts) + 1):
                        directories.add(CLASSES + "/".join(parts[:depth]) + "/")
                for name in sorted(directories):
                    entry = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                    entry.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
                    entry.compress_type = zipfile.ZIP_STORED
                    packaged.writestr(entry, b"")
                for name, data in sorted(content.items()):
                    entry = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                    entry.external_attr = (stat.S_IFREG | 0o644) << 16
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    packaged.writestr(entry, data)
            output.flush()
            os.fsync(output.fileno())
        except BaseException:
            destination.unlink()
            raise
    try:
        output_data = regular_bytes(destination)
        output_libraries, _ = inspect_base(output_data)
        if libraries != output_libraries:
            raise ValueError("packaging changed dependency contents")
        with checked_archive(base_data) as original, checked_archive(output_data) as packaged:
            original_kept = {name for name in original.namelist() if not name.startswith(CLASSES)}
            packaged_kept = {name for name in packaged.namelist() if not name.startswith(CLASSES)}
            if original_kept != packaged_kept or any(original.read(name) != packaged.read(name) for name in original_kept):
                raise ValueError("packaging changed loader or metadata contents")
        report.update({"output": str(destination), "output_sha256": sha256(output_data),
                       "dependencies_unchanged": True, "loader_and_metadata_unchanged": True,
                       "application_file_count": len(content)})
    except BaseException:
        destination.unlink()
        raise
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect_parser = commands.add_parser("inspect", help="verify the base and extract libraries into a new directory")
    inspect_parser.add_argument("base", type=Path)
    inspect_parser.add_argument("destination", type=Path)
    package_parser = commands.add_parser("package", help="replace only BOOT-INF/classes in a new JAR")
    package_parser.add_argument("base", type=Path)
    package_parser.add_argument("classes", type=Path)
    package_parser.add_argument("resources", type=Path)
    package_parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "inspect":
            report = extract_libraries(args.base, args.destination)
        else:
            report = package_application(args.base, args.classes, args.resources, args.destination)
        print(json.dumps(report, indent=2, sort_keys=True))
    except (OSError, ValueError, KeyError, UnicodeError, zipfile.BadZipFile, RuntimeError) as error:
        print("offline build refused: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
